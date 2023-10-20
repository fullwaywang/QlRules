/**
 * @name ffmpeg-a7e032a277452366771951e29fd0bf2bd5c029f0-rm_read_multi
 * @id cpp/ffmpeg/a7e032a277452366771951e29fd0bf2bd5c029f0/rm-read-multi
 * @description ffmpeg-a7e032a277452366771951e29fd0bf2bd5c029f0-libavformat/rmdec.c-rm_read_multi CVE-2018-1999013
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vmime_492, VariableAccess target_1) {
		target_1.getTarget()=vmime_492
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_rm_read_mdpr_codecdata")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pb"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="priv_data"
}

from Function func, Parameter vmime_492, VariableAccess target_1
where
func_1(vmime_492, target_1)
and vmime_492.getType().hasName("char *")
and vmime_492.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
