/**
 * @name linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-toneport_setup
 * @id cpp/linux/0b074ab7fc0d575247b9cc9f93bb7e007ca38840/toneport-setup
 * @description linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-toneport_setup 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtoneport_369) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="startup_work"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="line6"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtoneport_369)
}

predicate func_2(Parameter vtoneport_369) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="pcm_work"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtoneport_369)
}

from Function func, Parameter vtoneport_369
where
not func_0(vtoneport_369)
and func_2(vtoneport_369)
and vtoneport_369.getType().hasName("usb_line6_toneport *")
and vtoneport_369.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
