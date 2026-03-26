qemu-system-x86_64 \
    -device virtio-scsi-pci,id=scsi0 \
    -drive file=zso2026_cow.qcow2,if=none,id=drive0 \
    -device scsi-hd,bus=scsi0.0,drive=drive0 \
    -enable-kvm \
    -smp $(nproc) \
    -cpu max \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -m 4G \
    -device virtio-balloon \
    -display none
    # --nographic
