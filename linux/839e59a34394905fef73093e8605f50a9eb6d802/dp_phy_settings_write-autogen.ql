/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_phy_settings_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-phy-settings-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_phy_settings_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbuf_471, Parameter vsize_472, Variable vwr_buf_477, Variable vparam_479, Variable vmax_param_num_482, Variable vparam_nums_483) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_472
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_477
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_479
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_471
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_482
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_483
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_477
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vbuf_471, Parameter vsize_472, Variable vwr_buf_477, Variable vparam_479, Variable vmax_param_num_482, Variable vparam_nums_483
where
func_1(vbuf_471, vsize_472, vwr_buf_477, vparam_479, vmax_param_num_482, vparam_nums_483)
and vbuf_471.getType().hasName("const char *")
and vsize_472.getType().hasName("size_t")
and vwr_buf_477.getType().hasName("char *")
and vparam_479.getType().hasName("long[3]")
and vmax_param_num_482.getType().hasName("int")
and vparam_nums_483.getType().hasName("uint8_t")
and vbuf_471.getParentScope+() = func
and vsize_472.getParentScope+() = func
and vwr_buf_477.getParentScope+() = func
and vparam_479.getParentScope+() = func
and vmax_param_num_482.getParentScope+() = func
and vparam_nums_483.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
