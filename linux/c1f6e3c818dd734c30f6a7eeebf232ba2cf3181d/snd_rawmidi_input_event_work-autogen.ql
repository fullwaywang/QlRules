/**
 * @name linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_input_event_work
 * @id cpp/linux/c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d/snd_rawmidi_input_event_work
 * @description linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_input_event_work 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BuiltInOperationBuiltInOffsetOf target_0 |
		target_0.getValue()="240"
		and target_0.getChild(0).(TypeName).getType() instanceof Struct
		and target_0.getChild(1).(ValueFieldAccess).getTarget().getName()="event_work"
		and target_0.getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand() instanceof Literal
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
