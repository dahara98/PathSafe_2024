# PathSafe: A Tool for Secure Path Verification in Software-Defined Networks

> **Abstract**.
Network topology discovery in software-defined networks (SDN) poses a significant challenge. No current method guarantees both security and efficiency in the discovery process, often resulting in unverified outcomes. This vulnerability allows attackers to deceive the controller into learning an incorrect topology, thereby endangering the entire network's security. The conventional topology services implemented within the controller are inherently insecure. Rather than attempting to rectify these vulnerabilities by altering the controller, this paper introduces _PathSafe_, a novel tool constructed on top of the existing controller framework. _PathSafe_ is designed for secure path verification in SDN environments, enabling the verification of all available paths between two points in the network and thus ensuring a secure topology verification process. Our approach, implemented within the data plane, allows real-time packet monitoring at line speed. Our research demonstrates that _PathSafe_ effectively mitigates security risks in compromised switches and host scenarios. Alongside a theoretical exploration of this challenge, we present a proof of concept realised through programmable data planes, underscoring the practical applicability of our solution. This is achieved by employing P4, a domain-specific programming language.

Submitted at `CNSM 2024` with submission name `1571045700`.

## Directory Structure Overview

This directory houses all the essential implementation files for the _PathSafe_ tool, located within the `Protocol` folder.

## Instructions

Our solution utilises the [virtual machines (VMs)](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md). Specifically, we have employed the Development VM Image for Ubuntu 20.04. Please refer to the `README.md` in `Protocol` folder for further instructions on running our solution.
