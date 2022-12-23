/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_passthrough_set
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-dsc-passthrough-set
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_passthrough_set CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbuf_901, Parameter vsize_902, Variable vwr_buf_905, Variable vmax_param_num_907, Variable vparam_908, Variable vparam_nums_909) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_902
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_905
		and target_1.getParent().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_908
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_901
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_907
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_909
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_905
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vbuf_901, Parameter vsize_902, Variable vwr_buf_905, Variable vmax_param_num_907, Variable vparam_908, Variable vparam_nums_909
where
func_1(vbuf_901, vsize_902, vwr_buf_905, vmax_param_num_907, vparam_908, vparam_nums_909)
and vbuf_901.getType().hasName("const char *")
and vsize_902.getType().hasName("size_t")
and vwr_buf_905.getType().hasName("char *")
and vmax_param_num_907.getType().hasName("int")
and vparam_908.getType().hasName("long")
and vparam_nums_909.getType().hasName("uint8_t")
and vbuf_901.getParentScope+() = func
and vsize_902.getParentScope+() = func
and vwr_buf_905.getParentScope+() = func
and vmax_param_num_907.getParentScope+() = func
and vparam_908.getParentScope+() = func
and vparam_nums_909.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
