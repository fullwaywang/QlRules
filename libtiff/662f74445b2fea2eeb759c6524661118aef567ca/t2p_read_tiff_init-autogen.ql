/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-t2p_read_tiff_init
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/t2p-read-tiff-init
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-tools/tiff2pdf.c-t2p_read_tiff_init CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vt2p_1029, Parameter vinput_1029, Variable vi_1032, Variable vxuint16_1035, LogicalAndExpr target_1, ArrayExpr target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="tiles_tilecount"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tiff_tiles"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1032
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vxuint16_1035
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="tiff2pdf"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid tile count, %s"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1029
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="t2p_error"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignDivExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vinput_1029, Variable vxuint16_1035, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1029
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="284"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxuint16_1035
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vxuint16_1035
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_2(Parameter vt2p_1029, Variable vi_1032, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="tiff_pages"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vi_1032
}

predicate func_3(Parameter vt2p_1029, Variable vi_1032, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="tiff_tiles"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_1032
}

predicate func_4(Parameter vinput_1029, Variable vxuint16_1035, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1029
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="277"
		and target_4.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxuint16_1035
}

predicate func_5(Parameter vt2p_1029, Parameter vinput_1029, Variable vi_1032, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1029
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="322"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="tiles_tilewidth"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tiff_tiles"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1032
}

predicate func_6(Variable vxuint16_1035, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vxuint16_1035
}

predicate func_7(Parameter vt2p_1029, Variable vi_1032, Variable vxuint16_1035, ExprStmt target_7) {
		target_7.getExpr().(AssignDivExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tiles_tilecount"
		and target_7.getExpr().(AssignDivExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tiff_tiles"
		and target_7.getExpr().(AssignDivExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_1029
		and target_7.getExpr().(AssignDivExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1032
		and target_7.getExpr().(AssignDivExpr).getRValue().(VariableAccess).getTarget()=vxuint16_1035
}

from Function func, Parameter vt2p_1029, Parameter vinput_1029, Variable vi_1032, Variable vxuint16_1035, LogicalAndExpr target_1, ArrayExpr target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7
where
not func_0(vt2p_1029, vinput_1029, vi_1032, vxuint16_1035, target_1, target_2, target_3, target_4, target_5, target_6, target_7)
and func_1(vinput_1029, vxuint16_1035, target_1)
and func_2(vt2p_1029, vi_1032, target_2)
and func_3(vt2p_1029, vi_1032, target_3)
and func_4(vinput_1029, vxuint16_1035, target_4)
and func_5(vt2p_1029, vinput_1029, vi_1032, target_5)
and func_6(vxuint16_1035, target_6)
and func_7(vt2p_1029, vi_1032, vxuint16_1035, target_7)
and vt2p_1029.getType().hasName("T2P *")
and vinput_1029.getType().hasName("TIFF *")
and vi_1032.getType().hasName("tdir_t")
and vxuint16_1035.getType().hasName("uint16")
and vt2p_1029.getFunction() = func
and vinput_1029.getFunction() = func
and vi_1032.(LocalVariable).getFunction() = func
and vxuint16_1035.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
