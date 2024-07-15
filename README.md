# PathSafe: A Tool for Secure Path Verification in Software-Defined Networks

> **Abstract**.
Network topology verification in Software-Defined Networks (SDN) poses a significant challenge, as vulnerabilities can allow attackers to deceive the controller and manipulate the data plane into incorrect topologies, thereby endangering the entire network's security. Current solutions fail to guarantee both security and efficiency in the verification process, often resulting in damaging user traffic.
With the aim of solving joint objectives, in this paper, we introduce _PathSafe_, a novel tool constructed on top of the existing controller frameworks designed for secure path verification in SDN environments. It enables the verification of all available paths between two points in the network and ensures a secure process. Our approach requires a data plane component for real-time packet monitoring at line speed and a control plane verification step. Our research demonstrates that _PathSafe_ effectively mitigates security risks in compromised switches and host scenarios. Alongside a theoretical exploration of this challenge, we present a proof of concept implemented in P4, a common language for programmable data planes. Results obtained in Mininet underscore the practical applicability of _PathSafe_ that, compared to alternatives, can reduce overhead in the verification process while maintaining a limited execution time.

Submitted at `CNSM 2024` with submission name `1571045700`.

## Directory Structure Overview

This directory houses all the essential implementation files for the _PathSafe_ tool, located within the `Protocol` folder.

## Instructions

Our solution utilises the [virtual machines (VMs)](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md). Specifically, we have employed the Development VM Image for Ubuntu 20.04. Please refer to the `README.md` in `Protocol` folder for further instructions on running our solution.
