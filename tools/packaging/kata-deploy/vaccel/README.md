Label each node where vAccel-kata should be deployed:

```
kubectl label nodes <your-node-name> vaccel=true
```

Create service account and cluster role for the kata-deploy daemon
```
kubectl apply -f kata-rbac.yaml
```

The following will install the kata-deploy daemon on each "vaccel=true" node
It will also additionally label each node with katacontainers.io/kata-runtime: "true"

```
kubectl apply -f kata-vaccel-deploy/base/kata-deploy-select.yaml
```

Finally create 3 Runtime Classes 

```
kubectl apply -f kata-vaccel-rc.yaml
```

The RuntimeClass config uses the katacontainers.io/kata-runtime: "true" nodeSelector from the previous step. Pods using this RuntimeClass can only be scheduled to a node matched by this selector. The RuntimeClass nodeSelector is merged with a pod’s existing nodeSelector. Any conflicts will cause the pod to be rejected in admission. At the end any pod using one of these Runtime Classes can only be scheduled in a vaccel: "true" node as the deploy deamon run only on those nodes creating the extra label kata-runtime: "true"

###Run the examples

```
kubectl apply -f example-apps/classify-virtio.yaml  
kubectl apply -f example-apps/classify-vsock.yaml
```

###Delete kata-vaccel
First delete the pods using the RuntimeClasses

Then,

Delete the daemon, this will also label each node with kata-runtime: "cleanup"

```
kubectl delete -f kata-vaccel-deploy/base/kata-deploy-select.yaml
```

Run the kata-cleanup to reset the runtime 
(it already has a node selector for the kata-runtime: "cleanup" label created in the previous step)

```
kubectl apply -f kata-cleanup.yaml
```

Delete the RuntimeClass configuration

```
kubectl delete -f kata-vaccel-rc.yaml
```

Delete service account and cluster roles
```
kubectl delete -f kata-rbac.yaml
```

Finally delete the kata-cleanup daemon 
```
kubectl delete -f kata-cleanup.yaml
```
