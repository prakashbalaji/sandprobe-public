# sandprobe-recipe: v1
# provider: local Docker, one container from an image of your own
# docs: https://docs.docker.com/reference/cli/docker/
# terms: Docker Engine runs on your machine and the image is yours, so no provider's terms apply.
# exclusions: SEC-4 EGR-3 AMP-6 AMP-7
# addressed-by: id
# env: SANDPROBE_TEMPLATE SANDPROBE_AGENT_USER
#
# An example of a recipe of your own, for `sandprobe run -recipe` (RCP-4, docs/providers/recipe.md). It is NOT a
# shipped recipe: it isn't built into sandprobe, has no PRV row in SPEC.md, and Sandprobe treats it like any file you
# name, as code nobody reviewed. Copy it, and change sp_create and sp_shell to start a box from your own template and
# to reach it the way your agents do.
#
#   SANDPROBE_TEMPLATE    required: the local image to start the box from, the "template" you hardened
#   SANDPROBE_AGENT_USER  the user your agent runs as in the box (default "agent")
#
#   SANDPROBE_TEMPLATE=my-agent:hardened sandprobe plan -recipe examples/recipes/docker-template.sh -as agent
#   SANDPROBE_TEMPLATE=my-agent:hardened sandprobe run -recipe examples/recipes/docker-template.sh -as agent -y

# sp_say is the recipe's own message, on fd 3: the only output of a recipe Sandprobe shows. Its stderr is never shown,
# since a tool can print a credential there.
sp_say() { { echo "$*" >&3; } 2>/dev/null; }

# Every docker runs with fd 3 closed, so no tool can write a message as the recipe.
sp_docker() { docker "$@"; } 3>&-

sp_user() { printf '%s' "${SANDPROBE_AGENT_USER:-agent}"; }

# sp_engine names the Docker engine the docker CLI points at, by its name and ID.
sp_engine() { sp_docker info --format 'Docker engine {{.Name}} ({{.ID}})'; }

# sp_image is the image the template names right now, by its immutable ID, never pulled.
sp_image() { sp_docker image inspect --format '{{.Id}}' "$SANDPROBE_TEMPLATE"; }

# sp_target names where the box will be made and from what: the engine, the template as the image ID it means now,
# and the agent's user. The plan shows this line. Sandprobe hands it back as SANDPROBE_TARGET on every later call.
sp_target() {
	sp_e=$(sp_engine) && sp_i=$(sp_image) || return 1
	case $sp_i in sha256:?*) ;; *) return 1 ;; esac
	printf '%s, template %s as image %s, agent user %s\n' "$sp_e" "$SANDPROBE_TEMPLATE" "$sp_i" "$(sp_user)"
}

# sp_bound: create and shell refuse unless the engine, the image behind the template and the user are still the ones
# the plan named (RCP-1).
sp_bound() {
	if [ -z "$SANDPROBE_TARGET" ] || [ "$(sp_target)" != "$SANDPROBE_TARGET" ]; then
		sp_say "the engine, the template's image or the user is no longer what the plan said"
		return 1
	fi
}

# sp_same_engine: delete and gone need only the same engine, so a template retagged mid-run can't stop the cleanup.
sp_same_engine() {
	sp_e=$(sp_engine) || return 1
	case $SANDPROBE_TARGET in "$sp_e, template "*) [ -n "$SANDPROBE_BOX" ] ;; *) return 1 ;; esac
}

# sp_ready checks the settings and prints the one line that names the target. It creates nothing. Sandprobe runs it
# before the plan, so before you approve anything.
sp_ready() {
	command -v docker >/dev/null 2>&1 || { sp_say "docker isn't on PATH"; return 1; }
	case ${SANDPROBE_TEMPLATE:-} in '' | -*)
		sp_say "set SANDPROBE_TEMPLATE to the local image to start the box from"
		return 1
		;;
	esac
	case $(sp_user) in -*) sp_say "SANDPROBE_AGENT_USER isn't a user name or a uid"; return 1 ;; esac
	sp_engine >/dev/null || { sp_say "docker can't reach its engine"; return 1; }
	sp_target || { sp_say "there is no local image $SANDPROBE_TEMPLATE; build or pull it first, since this recipe never pulls"; return 1; }
}

# sp_create makes one container from the image the plan named and prints only its ID, the whole 64 hex digits docker
# create returns. The ID is printed before the start, so a container that fails to start is still deleted by it. The
# container removes itself when it stops, and stops by itself after an hour if the cleanup never comes.
sp_create() {
	sp_bound || return 1
	sp_i=$(sp_image) || return 1
	sp_id=$(sp_docker create --pull never --rm --name "$SANDPROBE_NAME" --label managed-by=sandprobe \
		--entrypoint sleep "$sp_i" 3600) || { sp_say "docker create failed"; return 1; }
	echo "$sp_id"
	sp_docker start "$sp_id" >/dev/null || { sp_say "the container didn't start"; return 1; }
}

# sp_shell opens sh in the box as the agent's user, with stdin attached: the entry Sandprobe sends the probe through.
sp_shell() {
	sp_bound || return 1
	exec docker exec -i -u "$(sp_user)" "$SANDPROBE_BOX" sh 3>&-
}

# sp_delete removes the container by the ID its create returned, and by nothing else.
sp_delete() {
	sp_same_engine || return 1
	sp_docker rm -f "$SANDPROBE_BOX" >/dev/null
}

# sp_gone: 0 only when the engine lists no container with that ID, 1 while it lists ours, 2 when docker can't say.
sp_gone() {
	sp_same_engine || return 2
	sp_now=$(sp_docker ps -a --no-trunc --filter "id=$SANDPROBE_BOX" --format '{{.ID}}') || return 2
	[ -z "$sp_now" ] && return 0
	[ "$sp_now" = "$SANDPROBE_BOX" ] && return 1
	return 2
}
