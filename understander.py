import os
import json
import csv

currentDir = os.getcwd()
dir = os.listdir()
dict = {}
# github, syft, cyclone
resultsDict = {}

relationshipDict = {}

packageDict = {}
for folder_name in dir:
    folder_path = os.path.join(currentDir, folder_name)

    # Check if the current item is a directory
    if os.path.isdir(folder_path):
        print(f"Contents of folder '{folder_name}':")

        # Iterate over each file in the current folder
        resultsDict[folder_name] = [0,0,0]
        relationshipDict[folder_name] = [0,0,0]
        packageDict[folder_name] = [0,0,0,0]

        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)

            # Check if the current item is a file
            if os.path.isfile(file_path):
                # Read and print the contents of the file
                with open(file_path, 'rb') as file:
                    try:
                        json_contents = json.load(file)
                        dict[file_name] = json_contents
                    except json.JSONDecodeError as e:
                        print(f"  Error decoding JSON in file '{file_name}': {e}\n")


                if ('github' in file_name):
                    resultsDict[folder_name][0] = len(dict[file_name]["packages"])
                    relationshipDict[folder_name][0] = len(dict[file_name]["relationships"])
                    githubNames_array = [package.get("name", "") for package in dict[file_name]["packages"]]
                    githubName = dict[file_name]["name"].split("/")[0] + "/"
                    print(githubName)

                    githubNames_array = [name.split(githubName)[-1] for name in githubNames_array]
                    githubNames_array = [name.split(":",2)[-1] for name in githubNames_array]

                    print(githubNames_array)
                    print("\n")

                elif ("sbom" in file_name):
                    resultsDict[folder_name][1] = len(dict[file_name]["artifacts"])
                    relationshipDict[folder_name][1] = len(dict[file_name]["artifactRelationships"])
                    sbomNames_array = [package.get("name", "") for package in dict[file_name]["artifacts"]]
                    print("sbom")
                    print(sbomNames_array)
                    print("\n")


                elif ("Cyclone" in file_name):
                    resultsDict[folder_name][2] = len(dict[file_name]["components"])
                    relationshipDict[folder_name][2] = len(dict[file_name]["dependencies"])
                    cycloneNames_array = [package.get("name", "") for package in dict[file_name]["components"]]
                    print("cyclone")

                    print(cycloneNames_array)
                    print("\n")
        common = set(githubNames_array) & set(sbomNames_array) & set(cycloneNames_array)

        unique_to_cyclone = set(cycloneNames_array) - set(githubNames_array) - set(sbomNames_array)
        unique_to_github = set(githubNames_array) - set(sbomNames_array) - set(cycloneNames_array)
        unique_to_sbom = set(sbomNames_array) - set(githubNames_array) - set(cycloneNames_array)

        packageDict[folder_name][0] = len(list(common))
        packageDict[folder_name][1] = len(list(unique_to_github))
        packageDict[folder_name][2] = len(list(unique_to_sbom))
        packageDict[folder_name][3] = len(list(unique_to_cyclone))


with open("resultsFile.csv", 'w') as file:
    writer = csv.writer(file)
    # writer.writerow(resultsDict.keys())
    writer.writerows(resultsDict.values())

with open("relationship.csv", 'w') as file:
    writer = csv.writer(file)
    # writer.writerow(resultsDict.keys())
    writer.writerows(relationshipDict.values())

with open("dependenciesUnique.csv", 'w') as file:
    writer = csv.writer(file)
    # writer.writerow(resultsDict.keys())
    for row in packageDict.values():
        cleaned_array = [str(s).replace('\n', '') for s in row]

        writer.writerow(cleaned_array)
