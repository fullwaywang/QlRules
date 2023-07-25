/**
 * @name ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-cdj970_print_page
 * @id cpp/ghostscript/4f73e8b4d578e69a17f452fa60d2130c5faaefd6/cdj970-print-page
 * @description ghostscript-4f73e8b4d578e69a17f452fa60d2130c5faaefd6-contrib/gdevdj9.c-cdj970_print_page CVE-2020-16291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vprn_stream_830, Parameter vpdev_830, ExprStmt target_3, LogicalAndExpr target_4, ArrayExpr target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cdj970_write_header")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpdev_830
		and target_0.getArgument(1).(VariableAccess).getTarget()=vprn_stream_830
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(ExprCall).getArgument(2).(VariableAccess).getLocation())
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpdev_830, VariableAccess target_1) {
		target_1.getTarget()=vpdev_830
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vpdev_830, FunctionCall target_2) {
		target_2.getTarget().hasName("cdj970_one_time_initialisation")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vpdev_830
}

predicate func_3(Parameter vprn_stream_830, Parameter vpdev_830, ExprStmt target_3) {
		target_3.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="start_raster_mode"
		and target_3.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_830
		and target_3.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vpdev_830
		and target_3.getExpr().(ExprCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="paper_size"
		and target_3.getExpr().(ExprCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("misc_struct")
		and target_3.getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget()=vprn_stream_830
}

predicate func_4(Parameter vpdev_830, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="PageCtr"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_830
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ptype"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_830
}

predicate func_5(Parameter vpdev_830, ArrayExpr target_5) {
		target_5.getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_5.getArrayOffset().(PointerFieldAccess).getTarget().getName()="ptype"
		and target_5.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_830
}

from Function func, Parameter vprn_stream_830, Parameter vpdev_830, VariableAccess target_1, FunctionCall target_2, ExprStmt target_3, LogicalAndExpr target_4, ArrayExpr target_5
where
not func_0(vprn_stream_830, vpdev_830, target_3, target_4, target_5)
and func_1(vpdev_830, target_1)
and func_2(vpdev_830, target_2)
and func_3(vprn_stream_830, vpdev_830, target_3)
and func_4(vpdev_830, target_4)
and func_5(vpdev_830, target_5)
and vprn_stream_830.getType().hasName("gp_file *")
and vpdev_830.getType().hasName("gx_device_printer *")
and vprn_stream_830.getFunction() = func
and vpdev_830.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
