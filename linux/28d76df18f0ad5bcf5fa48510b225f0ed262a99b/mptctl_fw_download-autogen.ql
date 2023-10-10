/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_fw_download
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_fw_download
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_fw_download 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vufwdl_759) {
	exists(Literal target_0 |
		target_0.getValue()="765"
		and not target_0.getValue()="758"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::_ioctl_fwdl - Unable to copy mpt_fw_xfer struct @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vufwdl_759)
}

predicate func_2(Variable vkfwdl_760) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="iocnum"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkfwdl_760)
}

from Function func, Variable vufwdl_759, Variable vkfwdl_760
where
func_0(vufwdl_759)
and func_2(vkfwdl_760)
and vufwdl_759.getType().hasName("mpt_fw_xfer *")
and vkfwdl_760.getType().hasName("mpt_fw_xfer")
and vufwdl_759.getParentScope+() = func
and vkfwdl_760.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
