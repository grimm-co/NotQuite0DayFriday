#!/bin/bash

echo "owned by root" > /tmp/proof
chmod +x /tmp/proof
chmod u+s /tmp/proof
