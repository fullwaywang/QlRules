/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-trigger_hotplug
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/trigger-hotplug
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-trigger_hotplug CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbuf_1191, Parameter vsize_1192, Variable vwr_buf_1199, Variable vmax_param_num_1201, Variable vparam_1202, Variable vparam_nums_1203) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_1192
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1199
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_1202
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_1191
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_1201
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_1203
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1199
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vbuf_1191, Parameter vsize_1192, Variable vwr_buf_1199, Variable vmax_param_num_1201, Variable vparam_1202, Variable vparam_nums_1203
where
func_1(vbuf_1191, vsize_1192, vwr_buf_1199, vmax_param_num_1201, vparam_1202, vparam_nums_1203)
and vbuf_1191.getType().hasName("const char *")
and vsize_1192.getType().hasName("size_t")
and vwr_buf_1199.getType().hasName("char *")
and vmax_param_num_1201.getType().hasName("int")
and vparam_1202.getType().hasName("long[1]")
and vparam_nums_1203.getType().hasName("uint8_t")
and vbuf_1191.getParentScope+() = func
and vsize_1192.getParentScope+() = func
and vwr_buf_1199.getParentScope+() = func
and vmax_param_num_1201.getParentScope+() = func
and vparam_1202.getParentScope+() = func
and vparam_nums_1203.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
