## Running the Protocol

To run our solution, please proceed with the steps below:

1. Download and initiate the designated [VM](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md).
2. Adhere to the instructions provided in the [P4 learning](https://github.com/nsg-ethz/p4-learning).
3. Clone this repository under `P4-learning/exercises`.
4. Execute the following commands inside `Protocol` to start the simulation:

# Run mininet with P4-enabled switches
```bash
sudo p4run
```

# Start the controller
```bash
sudo python3 controller.py
```

# Run the traffic inside hosts
```bash
xterm h1
./h1_script.sh
```

The remainder of the directory encompasses all required files for the simulation's execution, containing topology data files, switch behaviour configurations and other essential build documents.
