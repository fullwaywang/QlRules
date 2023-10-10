/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_clock_en_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-dsc-clock-en-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_clock_en_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vmax_param_num_1389, Variable vparam_1390, Variable vparam_nums_1391, Parameter vbuf_1377, Parameter vsize_1378, Variable vwr_buf_1387) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_1378
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1387
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_1390
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_1377
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_1389
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_1391
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1387
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Variable vmax_param_num_1389, Variable vparam_1390, Variable vparam_nums_1391, Parameter vbuf_1377, Parameter vsize_1378, Variable vwr_buf_1387
where
func_1(vmax_param_num_1389, vparam_1390, vparam_nums_1391, vbuf_1377, vsize_1378, vwr_buf_1387)
and vmax_param_num_1389.getType().hasName("int")
and vparam_1390.getType().hasName("long[1]")
and vparam_nums_1391.getType().hasName("uint8_t")
and vbuf_1377.getType().hasName("const char *")
and vsize_1378.getType().hasName("size_t")
and vwr_buf_1387.getType().hasName("char *")
and vmax_param_num_1389.getParentScope+() = func
and vparam_1390.getParentScope+() = func
and vparam_nums_1391.getParentScope+() = func
and vbuf_1377.getParentScope+() = func
and vsize_1378.getParentScope+() = func
and vwr_buf_1387.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
