#!/usr/bin/env ruby
require 'yaml'
require 'json'
#
# script that dumps the ethos fleet (though based on the KUBECONFIG env variable) can be any list of contexts
# so the fleet can be compared to argocd (and the output from ./generate_helm.rb ) for accuracy
#

# Get the list of contexts
contexts = `kubectl config get-contexts -o name`.split("\n")

def deep_sort_hash(obj)
    return obj unless obj.is_a?(Hash)
    Hash[obj.sort.map { |k, v| [k, deep_sort_hash(v)] }]
end

# Loop over each context
contexts.each do |context|
  begin
    puts context

    # Create a directory for the context
    Dir.mkdir(context) unless Dir.exist?(context)

    # Change to the newly created directory
    Dir.chdir(context) do
      # Run kubectl command to get deployments, configmaps, and services as YAML in the 'heptio-contour' namespace
      command_output = `kubectl --context=#{context} get -A httpproxies,ingressroutes,RequestProcessing -o yaml`

      # If the command fails, raise an error
      raise "Unable to connect to the context #{context}" unless $?.success?

      # Load and process the YAML output
      yaml_data = YAML.load_stream(command_output)[0]["items"]

      selected_items = yaml_data.select { |t| !t.nil? && t.key?("kind") }

      # Iterate over each selected item
      selected_items.each do |item|

        kind = item["kind"]
        item.delete("status")

        metadata = item["metadata"]
        namespace = metadata.fetch("namespace", "default")
        name = metadata.fetch("name", metadata.fetch("generatedName", "missing"))

        # Remove unwanted metadata keys for comparison sake
        %w[annotations managedFields generation creationTimestamp selfLink uid resourceVersion].each do |key|
          metadata.delete(key)
        end

        if item["kind"] == "Deployment"  # Check if the kind is Deployment
          containers = item.dig("spec", "template", "spec", "containers")  # Navigate to containers array
          next unless containers  # Skip if containers not found
          if containers
            containers.reject! { |container| container["name"] == "fluent-bit" }
          end
          ports = item.dig("spec", "template",  "ports")  # Navigate to containers array
          containers.each do |container|  # Iterate over each container
            envs = container["env"]  # Extract env array
            next unless envs  # Skip if env not found
            # Sort env array by name field
            container["env"] = envs.sort_by { |env| env["name"] }
            container["ports"] = container["ports"].sort_by { |port| port["name"] }.map{|hash| Hash[hash.sort]} if container.has_key?("ports")
          end
        end
        # Create filename and write the YAML file
        filename = "#{kind}-#{name}-#{namespace}.yaml"
        puts filename
        File.open(filename, "w") { |f| f.write(deep_sort_hash(item).to_yaml) }
      end
    end
  rescue => e
    puts e.message
  end
end
