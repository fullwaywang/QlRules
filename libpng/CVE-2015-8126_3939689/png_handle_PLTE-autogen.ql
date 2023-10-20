/**
 * @name libpng-3939689e7d9d06ee05411210bc8e605adcff294e-png_handle_PLTE
 * @id cpp/libpng/3939689e7d9d06ee05411210bc8e605adcff294e/png-handle-PLTE
 * @description libpng-3939689e7d9d06ee05411210bc8e605adcff294e-pngrutil.c-png_handle_PLTE CVE-2015-8126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_crc_finish")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vlength_506, Variable vnum_509, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vlength_506
		and target_1.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnum_509
		and target_1.getRightOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_crc_finish")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlength_506, Variable vnum_509, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_509
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_506
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="3"
}

predicate func_3(Variable vnum_509, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vnum_509
}

predicate func_4(Variable vnum_509, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("png_set_PLTE")
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnum_509
}

from Function func, Parameter vlength_506, Variable vnum_509, Literal target_0, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4
where
func_0(func, target_0)
and not func_1(vlength_506, vnum_509, target_2, target_3, target_4)
and func_2(vlength_506, vnum_509, target_2)
and func_3(vnum_509, target_3)
and func_4(vnum_509, target_4)
and vlength_506.getType().hasName("png_uint_32")
and vnum_509.getType().hasName("int")
and vlength_506.getParentScope+() = func
and vnum_509.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
