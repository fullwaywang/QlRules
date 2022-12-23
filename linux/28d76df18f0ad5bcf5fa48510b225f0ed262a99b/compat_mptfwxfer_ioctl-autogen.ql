/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-compat_mptfwxfer_ioctl
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/compat_mptfwxfer_ioctl
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-compat_mptfwxfer_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable viocnumX_2831) {
	exists(Literal target_0 |
		target_0.getValue()="2844"
		and not target_0.getValue()="2731"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl::compat_mptfwxfer_ioctl @%d - ioc%d not found!\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=viocnumX_2831)
}

predicate func_2(Variable vkfw_2829) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="iocnum"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkfw_2829)
}

from Function func, Variable vkfw_2829, Variable viocnumX_2831
where
func_0(viocnumX_2831)
and func_2(vkfw_2829)
and vkfw_2829.getType().hasName("mpt_fw_xfer")
and viocnumX_2831.getType().hasName("int")
and vkfw_2829.getParentScope+() = func
and viocnumX_2831.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
