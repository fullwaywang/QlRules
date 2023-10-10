/**
 * @name libtiff-e813112545942107551433d61afd16ac094ff246-TIFFWriteDirectorySec
 * @id cpp/libtiff/e813112545942107551433d61afd16ac094ff246/TIFFWriteDirectorySec
 * @description libtiff-e813112545942107551433d61afd16ac094ff246-libtiff/tif_dirwrite.c-TIFFWriteDirectorySec CVE-2022-3599
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vndir_352, Variable vdir_353, Parameter vtif_349, VariableAccess target_1, AddressOfExpr target_2, AddressOfExpr target_3, NotExpr target_4, NotExpr target_5, ValueFieldAccess target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="td_fieldsset"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_349
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(DivExpr).getValue()="1"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="262144"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFWriteDirectoryTagShort")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_349
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vndir_352
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_353
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="334"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="td_numberofinks"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(33)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_5.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter visimage_349, VariableAccess target_1) {
		target_1.getTarget()=visimage_349
}

predicate func_2(Variable vndir_352, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vndir_352
}

predicate func_3(Variable vndir_352, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vndir_352
}

predicate func_4(Variable vndir_352, Variable vdir_353, Parameter vtif_349, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("TIFFWriteDirectoryTagAscii")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_349
		and target_4.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vndir_352
		and target_4.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_353
		and target_4.getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="333"
		and target_4.getOperand().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="td_inknameslen"
		and target_4.getOperand().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_4.getOperand().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_349
		and target_4.getOperand().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="td_inknames"
		and target_4.getOperand().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_4.getOperand().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_349
}

predicate func_5(Variable vndir_352, Variable vdir_353, Parameter vtif_349, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("TIFFWriteDirectoryTagSubifd")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_349
		and target_5.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vndir_352
		and target_5.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_353
}

predicate func_6(Parameter vtif_349, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="td_inknames"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_349
}

from Function func, Variable vndir_352, Variable vdir_353, Parameter visimage_349, Parameter vtif_349, VariableAccess target_1, AddressOfExpr target_2, AddressOfExpr target_3, NotExpr target_4, NotExpr target_5, ValueFieldAccess target_6
where
not func_0(vndir_352, vdir_353, vtif_349, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(visimage_349, target_1)
and func_2(vndir_352, target_2)
and func_3(vndir_352, target_3)
and func_4(vndir_352, vdir_353, vtif_349, target_4)
and func_5(vndir_352, vdir_353, vtif_349, target_5)
and func_6(vtif_349, target_6)
and vndir_352.getType().hasName("uint32_t")
and vdir_353.getType().hasName("TIFFDirEntry *")
and visimage_349.getType().hasName("int")
and vtif_349.getType().hasName("TIFF *")
and vndir_352.(LocalVariable).getFunction() = func
and vdir_353.(LocalVariable).getFunction() = func
and visimage_349.getFunction() = func
and vtif_349.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
