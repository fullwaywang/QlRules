/**
 * @name libtiff-40b00cfb32256d377608b4d4cd30fac338d0a0bc-createImageSection
 * @id cpp/libtiff/40b00cfb32256d377608b4d4cd30fac338d0a0bc/createImageSection
 * @description libtiff-40b00cfb32256d377608b4d4cd30fac338d0a0bc-tools/tiffcrop.c-createImageSection CVE-2022-0907
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsect_buff_7400, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsect_buff_7400
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="createImageSection"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate/reallocate section buffer"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsect_buff_ptr_7398, Variable vsect_buff_7400, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vsect_buff_ptr_7398
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsect_buff_7400
}

predicate func_3(Variable vsect_buff_7400, Function func, IfStmt target_3) {
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsect_buff_7400
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="createImageSection"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate/reallocate section buffer"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(Parameter vsect_buff_ptr_7398, Variable vsect_buff_7400, VariableAccess target_4) {
		target_4.getTarget()=vsect_buff_7400
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsect_buff_ptr_7398
}

*/
predicate func_5(Variable vsect_buff_7400, ExprStmt target_7, ExprStmt target_8, AssignExpr target_5) {
		target_5.getLValue() instanceof PointerDereferenceExpr
		and target_5.getRValue().(VariableAccess).getTarget()=vsect_buff_7400
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getRValue().(VariableAccess).getLocation())
		and target_5.getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_6(RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_6.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_7(Variable vsect_buff_7400, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsect_buff_7400
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_8(Variable vsect_buff_7400, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsect_buff_7400
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32_t")
}

from Function func, Parameter vsect_buff_ptr_7398, Variable vsect_buff_7400, PointerDereferenceExpr target_2, IfStmt target_3, AssignExpr target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vsect_buff_7400, target_6, target_7, target_8)
and func_2(vsect_buff_ptr_7398, vsect_buff_7400, target_2)
and func_3(vsect_buff_7400, func, target_3)
and func_5(vsect_buff_7400, target_7, target_8, target_5)
and func_6(target_6)
and func_7(vsect_buff_7400, target_7)
and func_8(vsect_buff_7400, target_8)
and vsect_buff_ptr_7398.getType().hasName("unsigned char **")
and vsect_buff_7400.getType().hasName("unsigned char *")
and vsect_buff_ptr_7398.getFunction() = func
and vsect_buff_7400.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
