/**
 * @name linux-362bca57f5d78220f8b5907b875961af9436e229-snd_pcm_control_ioctl
 * @id cpp/linux/362bca57f5d78220f8b5907b875961af9436e229/snd-pcm-control-ioctl
 * @description linux-362bca57f5d78220f8b5907b875961af9436e229-snd_pcm_control_ioctl CVE-2017-0861
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpcm_119) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="open_mutex"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcm_119
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_1(Variable vpcm_119) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="open_mutex"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcm_119)
}

predicate func_2(Variable vpcm_119) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="streams"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpcm_119)
}

from Function func, Variable vpcm_119
where
not func_0(vpcm_119)
and not func_1(vpcm_119)
and vpcm_119.getType().hasName("snd_pcm *")
and func_2(vpcm_119)
and vpcm_119.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
