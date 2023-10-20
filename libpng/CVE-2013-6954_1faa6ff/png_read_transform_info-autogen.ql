/**
 * @name libpng-1faa6ff32c648acfe3cf30a58d31d7aebc24968c-png_read_transform_info
 * @id cpp/libpng/1faa6ff32c648acfe3cf30a58d31d7aebc24968c/png-read-transform-info
 * @description libpng-1faa6ff32c648acfe3cf30a58d31d7aebc24968c-pngrtran.c-png_read_transform_info CVE-2013-6954
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_1821, EqualityOperation target_1, RelationalOperation target_2, IfStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="palette"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1821
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_error")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1821
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Palette is NULL in indexed image"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_1.getAnOperand().(BitwiseOrExpr).getValue()="3"
}

predicate func_2(Parameter vpng_ptr_1821, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_trans"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1821
		and target_2.getLesserOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vpng_ptr_1821, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="num_trans"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1821
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="transformations"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1821
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="33554432"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4"
}

from Function func, Parameter vpng_ptr_1821, EqualityOperation target_1, RelationalOperation target_2, IfStmt target_3
where
not func_0(vpng_ptr_1821, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vpng_ptr_1821, target_2)
and func_3(vpng_ptr_1821, target_3)
and vpng_ptr_1821.getType().hasName("png_structrp")
and vpng_ptr_1821.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
