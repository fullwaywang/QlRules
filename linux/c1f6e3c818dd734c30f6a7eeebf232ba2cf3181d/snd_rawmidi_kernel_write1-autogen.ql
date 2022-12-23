/**
 * @name linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_kernel_write1
 * @id cpp/linux/c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d/snd_rawmidi_kernel_write1
 * @description linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_kernel_write1 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vruntime_1329, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("snd_rawmidi_buffer_ref")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vruntime_1329
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable vruntime_1329, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("snd_rawmidi_buffer_unref")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vruntime_1329
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Variable vruntime_1329) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="lock"
		and target_2.getQualifier().(VariableAccess).getTarget()=vruntime_1329)
}

predicate func_3(Variable vruntime_1329) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="buffer_size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vruntime_1329)
}

from Function func, Variable vruntime_1329
where
not func_0(vruntime_1329, func)
and not func_1(vruntime_1329, func)
and vruntime_1329.getType().hasName("snd_rawmidi_runtime *")
and func_2(vruntime_1329)
and func_3(vruntime_1329)
and vruntime_1329.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
