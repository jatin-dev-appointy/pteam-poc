type FlowMapKeys = "SKIPGG" | "SKIPL" | "SKIPGGPL" | "ALL"

const FLOW_MAP: Record<FlowMapKeys, number[]> = {
  SKIPGG: [1010002], // base64 encoded -> U0tJUEdH
  SKIPL: [1010015], // base64 encoded ->/ U0tJUEw=
  SKIPGGPL: [1010002, 1010015], // base64 encoded -> U0tJUEdHUEw=
  ALL: [],
}

export { FLOW_MAP, FlowMapKeys }
