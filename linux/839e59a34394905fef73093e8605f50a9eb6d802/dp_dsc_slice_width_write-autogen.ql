/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_slice_width_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-dsc-slice-width-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_slice_width_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vwr_buf_1572, Variable vmax_param_num_1574, Variable vparam_1575, Variable vparam_nums_1576, Parameter vsize_1563, Parameter vbuf_1562) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_1563
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1572
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_1575
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_1562
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_1574
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_1576
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1572
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Variable vwr_buf_1572, Variable vmax_param_num_1574, Variable vparam_1575, Variable vparam_nums_1576, Parameter vsize_1563, Parameter vbuf_1562
where
func_1(vwr_buf_1572, vmax_param_num_1574, vparam_1575, vparam_nums_1576, vsize_1563, vbuf_1562)
and vwr_buf_1572.getType().hasName("char *")
and vmax_param_num_1574.getType().hasName("int")
and vparam_1575.getType().hasName("long[1]")
and vparam_nums_1576.getType().hasName("uint8_t")
and vsize_1563.getType().hasName("size_t")
and vbuf_1562.getType().hasName("const char *")
and vwr_buf_1572.getParentScope+() = func
and vmax_param_num_1574.getParentScope+() = func
and vparam_1575.getParentScope+() = func
and vparam_nums_1576.getParentScope+() = func
and vsize_1563.getParentScope+() = func
and vbuf_1562.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
