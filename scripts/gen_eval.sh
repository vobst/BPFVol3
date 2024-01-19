#!/usr/bin/env bash

set -ueo pipefail

function print_help {
    echo "You did something wrong!"
}

function cut_begin {
    echo "------------------ [ CUT BEGIN $1 ] ------------------"
}

function cut_end {
    echo "------------------ [ CUT END $1 ] ------------------"
}

if [[ $# -eq 0 ]]; then
    print_help
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -i | --image)
            IMAGE="$2"
            shift # past argument
            shift # past value
            ;;
        -* | --*)
            echo "Unknown option $1"
            print_help
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1") # save positional arg
            shift                   # past argument
            ;;
    esac
done

TIME=$(date --iso-8601=seconds)
OFILE="/io/output/__${TIME}__$IMAGE.eval"

# just to be sure...
rm -rf $OFILE*

# run all plugins and record: stdout, stderr, and if exit code != 0
for plugin in $(vol --help | grep -Eo '(linux\.\S+)'); do
    echo -en "${plugin}" >>$OFILE

    echo $(cut_begin $plugin) >>"${OFILE}.log"
    echo $(cut_begin $plugin) >>"${OFILE}.err.log"

    vol \
        -vvvvvvv \
        -f "/io/dumps/$IMAGE" \
        $plugin \
        > >(tee -a "${OFILE}.log") 2> >(tee -a "${OFILE}.err.log" >&2) &&
        echo -e "\ts" >>$OFILE ||
        echo -e "\tf" >>$OFILE

    echo $(cut_end $plugin) >>"${OFILE}.log"
    echo $(cut_end $plugin) >>"${OFILE}.err.log"
done

# record the symbols library that was used, we expect it to be only one
LIB=$(sed -En 's/DEBUG    volatility3.framework.automagic.symbol_finder: Using symbol library: file:\/\/\/opt\/vol\/volatility3\/volatility3\/symbols\/linux\/(.*?)/\1/p' "${OFILE}.err.log" | sort -u | tr -d '\n')

mv "$OFILE" \
    "/io/output/${TIME}__${IMAGE}__${LIB}__.eval"
mv "$OFILE.log" \
    "/io/output/${TIME}__${IMAGE}__${LIB}__.eval.log"
mv "$OFILE.err.log" \
    "/io/output/${TIME}__${IMAGE}__${LIB}__.eval.err.log"

exit 0
