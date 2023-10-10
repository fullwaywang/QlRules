/**
 * @name libtiff-7be2e452ddcf6d7abca88f41d3761e6edab72b22-t2p_read_tiff_size
 * @id cpp/libtiff/7be2e452ddcf6d7abca88f41d3761e6edab72b22/t2p-read-tiff-size
 * @description libtiff-7be2e452ddcf6d7abca88f41d3761e6edab72b22-tools/tiff2pdf.c-t2p_read_tiff_size CVE-2020-35524
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vt2p_1968, Parameter vinput_1968, Variable vk_1976, ExprStmt target_3, ExprStmt target_1, FunctionCall target_4, FunctionCall target_5, EqualityOperation target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pdf_compression"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tiff_photometric"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_1976
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("checkMultiply64")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFNumberOfStrips")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1968
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFStripSize")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1968
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt2p_1968
		and target_0.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(1) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vt2p_1968, Parameter vinput_1968, Variable vk_1976, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_1976
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("checkMultiply64")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFScanlineSize")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1968
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tiff_length"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt2p_1968
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vt2p_1968, Variable vk_1976, Function func, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tiff_planar"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_1976
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("checkMultiply64")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_1976
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tiff_samplesperpixel"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt2p_1968
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vt2p_1968, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="t2p_error"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
}

predicate func_4(Parameter vinput_1968, FunctionCall target_4) {
		target_4.getTarget().hasName("TIFFFileName")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vinput_1968
}

predicate func_5(Parameter vinput_1968, FunctionCall target_5) {
		target_5.getTarget().hasName("TIFFScanlineSize")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vinput_1968
}

predicate func_6(Parameter vt2p_1968, Variable vk_1976, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="tiff_datasize"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1968
		and target_6.getAnOperand().(VariableAccess).getTarget()=vk_1976
}

from Function func, Parameter vt2p_1968, Parameter vinput_1968, Variable vk_1976, ExprStmt target_1, IfStmt target_2, ExprStmt target_3, FunctionCall target_4, FunctionCall target_5, EqualityOperation target_6
where
not func_0(vt2p_1968, vinput_1968, vk_1976, target_3, target_1, target_4, target_5, target_6, func)
and func_1(vt2p_1968, vinput_1968, vk_1976, func, target_1)
and func_2(vt2p_1968, vk_1976, func, target_2)
and func_3(vt2p_1968, target_3)
and func_4(vinput_1968, target_4)
and func_5(vinput_1968, target_5)
and func_6(vt2p_1968, vk_1976, target_6)
and vt2p_1968.getType().hasName("T2P *")
and vinput_1968.getType().hasName("TIFF *")
and vk_1976.getType().hasName("uint64")
and vt2p_1968.getFunction() = func
and vinput_1968.getFunction() = func
and vk_1976.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
