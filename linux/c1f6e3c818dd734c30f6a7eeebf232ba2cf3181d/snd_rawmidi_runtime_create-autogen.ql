/**
 * @name linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_runtime_create
 * @id cpp/linux/c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d/snd_rawmidi_runtime_create
 * @description linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_runtime_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vruntime_125) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="336"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vruntime_125)
}

from Function func, Variable vruntime_125
where
func_0(vruntime_125)
and vruntime_125.getType().hasName("snd_rawmidi_runtime *")
and vruntime_125.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
