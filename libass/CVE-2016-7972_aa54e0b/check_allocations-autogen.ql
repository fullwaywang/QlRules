/**
 * @name libass-aa54e0b59200a994d50a346b5d7ac818ebcf2d4b-check_allocations
 * @id cpp/libass/aa54e0b59200a994d50a346b5d7ac818ebcf2d4b/check-allocations
 * @description libass-aa54e0b59200a994d50a346b5d7ac818ebcf2d4b-libass/ass_shaper.c-check_allocations CVE-2016-7972
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vshaper_95, Parameter vnew_size_95, RelationalOperation target_1, PointerDereferenceExpr target_2, LogicalOrExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="n_glyphs"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vshaper_95
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_size_95
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vshaper_95, Parameter vnew_size_95, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vnew_size_95
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="n_glyphs"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vshaper_95
}

predicate func_2(Parameter vshaper_95, PointerDereferenceExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="cmap"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vshaper_95
}

predicate func_3(Parameter vshaper_95, Parameter vnew_size_95, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="emblevels"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ass_try_realloc_array")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(CommaExpr).getRightOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cmap"
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vshaper_95
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ass_try_realloc_array")
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cmap"
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_size_95
		and target_3.getAnOperand().(NotExpr).getOperand().(CommaExpr).getRightOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
}

from Function func, Parameter vshaper_95, Parameter vnew_size_95, RelationalOperation target_1, PointerDereferenceExpr target_2, LogicalOrExpr target_3
where
not func_0(vshaper_95, vnew_size_95, target_1, target_2, target_3)
and func_1(vshaper_95, vnew_size_95, target_1)
and func_2(vshaper_95, target_2)
and func_3(vshaper_95, vnew_size_95, target_3)
and vshaper_95.getType().hasName("ASS_Shaper *")
and vnew_size_95.getType().hasName("size_t")
and vshaper_95.getParentScope+() = func
and vnew_size_95.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
