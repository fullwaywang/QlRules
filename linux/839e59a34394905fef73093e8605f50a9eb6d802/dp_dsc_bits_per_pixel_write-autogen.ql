/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_bits_per_pixel_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-dsc-bits-per-pixel-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_bits_per_pixel_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vmax_param_num_1937, Variable vparam_nums_1938, Variable vparam_1939, Parameter vsize_1926, Variable vwr_buf_1935, Parameter vbuf_1925) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_1926
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1935
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_1939
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_1925
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_1937
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_1938
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1935
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Variable vmax_param_num_1937, Variable vparam_nums_1938, Variable vparam_1939, Parameter vsize_1926, Variable vwr_buf_1935, Parameter vbuf_1925
where
func_1(vmax_param_num_1937, vparam_nums_1938, vparam_1939, vsize_1926, vwr_buf_1935, vbuf_1925)
and vmax_param_num_1937.getType().hasName("int")
and vparam_nums_1938.getType().hasName("uint8_t")
and vparam_1939.getType().hasName("long[1]")
and vsize_1926.getType().hasName("size_t")
and vwr_buf_1935.getType().hasName("char *")
and vbuf_1925.getType().hasName("const char *")
and vmax_param_num_1937.getParentScope+() = func
and vparam_nums_1938.getParentScope+() = func
and vparam_1939.getParentScope+() = func
and vsize_1926.getParentScope+() = func
and vwr_buf_1935.getParentScope+() = func
and vbuf_1925.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
