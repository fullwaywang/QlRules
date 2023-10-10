/**
 * @name ghostscript-93cb0c0adbd9bcfefd021d59c472388f67d3300d-jetp3852_print_page
 * @id cpp/ghostscript/93cb0c0adbd9bcfefd021d59c472388f67d3300d/jetp3852-print-page
 * @description ghostscript-93cb0c0adbd9bcfefd021d59c472388f67d3300d-devices/gdev3852.c-jetp3852_print_page CVE-2020-16290
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vline_size_78, Parameter vpdev_60, PointerArithmeticOperation target_1, FunctionCall target_2, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vline_size_78
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="768"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("emprintf_program_ident")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_60
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("gs_program_name")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("gs_revision_number")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_60
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="invalid resolution and/or width gives line_size = %d, max. is %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_size_78
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(3).(MulExpr).getValue()="768"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vline_size_78, PointerArithmeticOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget().getType().hasName("byte[768]")
		and target_1.getAnOperand().(VariableAccess).getTarget()=vline_size_78
}

predicate func_2(Parameter vpdev_60, FunctionCall target_2) {
		target_2.getTarget().hasName("gx_device_raster")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vpdev_60
		and target_2.getArgument(1).(Literal).getValue()="0"
}

predicate func_3(Parameter vpdev_60, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_60
}

from Function func, Variable vline_size_78, Parameter vpdev_60, PointerArithmeticOperation target_1, FunctionCall target_2, RelationalOperation target_3
where
not func_0(vline_size_78, vpdev_60, target_1, target_2, target_3)
and func_1(vline_size_78, target_1)
and func_2(vpdev_60, target_2)
and func_3(vpdev_60, target_3)
and vline_size_78.getType().hasName("int")
and vpdev_60.getType().hasName("gx_device_printer *")
and vline_size_78.(LocalVariable).getFunction() = func
and vpdev_60.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
