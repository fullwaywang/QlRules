/**
 * @name libtiff-69bfeec247899776b1b396651adb47436e5f1556-t2p_read_tiff_data
 * @id cpp/libtiff/69bfeec247899776b1b396651adb47436e5f1556/t2p-read-tiff-data
 * @description libtiff-69bfeec247899776b1b396651adb47436e5f1556-tools/tiff2pdf.c-t2p_read_tiff_data CVE-2017-11335
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vt2p_1258, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tiff_planar"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1258
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vt2p_1258, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="pdf_nopassthrough"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1258
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vt2p_1258, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tiff_compression"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1258
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("TIFFIsTiled")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFNumberOfStrips")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vt2p_1258, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pdf_transcode"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1258
}

from Function func, Parameter vt2p_1258, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vt2p_1258, target_2, target_3, target_1)
and func_1(vt2p_1258, target_2, target_1)
and func_2(vt2p_1258, target_2)
and func_3(vt2p_1258, target_3)
and vt2p_1258.getType().hasName("T2P *")
and vt2p_1258.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
