FROM postgres:15-alpine

RUN apk add --no-cache openssh openssh-client shadow \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh cart-app \
    && echo 'cart-app:AppP@ssw0rd' | chpasswd \
    && echo 'root:CartSSH!2026' | chpasswd \
    && mkdir -p /home/cart-app/.ssh \
    && ssh-keygen -t ed25519 -f /home/cart-app/.ssh/id_ed25519 -N '' \
    && cp /home/cart-app/.ssh/id_ed25519.pub /home/cart-app/.ssh/authorized_keys \
    && chown -R cart-app:cart-app /home/cart-app/.ssh \
    && chmod 700 /home/cart-app/.ssh \
    && chmod 600 /home/cart-app/.ssh/authorized_keys /home/cart-app/.ssh/id_ed25519 \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
    && mkdir -p /var/run/sshd

COPY init.sql /docker-entrypoint-initdb.d/001-init.sql
COPY credentials.txt /home/cart-app/credentials.txt
COPY entrypoint.sh /usr/local/bin/cart-entrypoint.sh

RUN chmod +x /usr/local/bin/cart-entrypoint.sh \
    && chown cart-app:cart-app /home/cart-app/credentials.txt \
    && chmod 600 /home/cart-app/credentials.txt

EXPOSE 22 5432
ENTRYPOINT ["/usr/local/bin/cart-entrypoint.sh"]
CMD ["postgres"]
