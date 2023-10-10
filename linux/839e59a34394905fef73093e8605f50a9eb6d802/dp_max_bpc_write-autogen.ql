/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_max_bpc_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-max-bpc-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_max_bpc_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbuf_2366, Parameter vsize_2367, Variable vwr_buf_2373, Variable vmax_param_num_2375, Variable vparam_2376, Variable vparam_nums_2377) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_2367
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_2373
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_2376
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_2366
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_2375
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_2377
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_2373
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vbuf_2366, Parameter vsize_2367, Variable vwr_buf_2373, Variable vmax_param_num_2375, Variable vparam_2376, Variable vparam_nums_2377
where
func_1(vbuf_2366, vsize_2367, vwr_buf_2373, vmax_param_num_2375, vparam_2376, vparam_nums_2377)
and vbuf_2366.getType().hasName("const char *")
and vsize_2367.getType().hasName("size_t")
and vwr_buf_2373.getType().hasName("char *")
and vmax_param_num_2375.getType().hasName("int")
and vparam_2376.getType().hasName("long[1]")
and vparam_nums_2377.getType().hasName("uint8_t")
and vbuf_2366.getParentScope+() = func
and vsize_2367.getParentScope+() = func
and vwr_buf_2373.getParentScope+() = func
and vmax_param_num_2375.getParentScope+() = func
and vparam_2376.getParentScope+() = func
and vparam_nums_2377.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
