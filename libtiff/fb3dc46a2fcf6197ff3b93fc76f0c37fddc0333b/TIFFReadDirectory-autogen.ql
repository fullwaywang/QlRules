/**
 * @name libtiff-fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b-TIFFReadDirectory
 * @id cpp/libtiff/fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b/TIFFReadDirectory
 * @description libtiff-fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b-libtiff/tif_dirread.c-TIFFReadDirectory CVE-2017-9403
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtif_3413, Variable vmodule_3415, PointerFieldAccess target_2, ExprStmt target_3, NotExpr target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="td_stripoffset"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_3415
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="tif->tif_dir.td_stripoffset is already allocated. Likely duplicated StripOffsets/TileOffsets tag"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtif_3413, Variable vmodule_3415, PointerFieldAccess target_2, AddressOfExpr target_6, NotExpr target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_3415
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="tif->tif_dir.td_stripbytecount is already allocated. Likely duplicated StripByteCounts/TileByteCounts tag"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_6.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(PointerFieldAccess target_2) {
		target_2.getTarget().getName()="tdir_tag"
		and target_2.getQualifier().(VariableAccess).getTarget().getType().hasName("TIFFDirEntry *")
}

predicate func_3(Parameter vtif_3413, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_4(Parameter vtif_3413, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("TIFFFetchStripThing")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3413
		and target_4.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TIFFDirEntry *")
		and target_4.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="td_nstrips"
		and target_4.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_4.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_4.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="td_stripoffset"
		and target_4.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_4.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
}

predicate func_5(Parameter vtif_3413, Variable vmodule_3415, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("TIFFReadDirEntryOutputErr")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3413
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TIFFReadDirEntryErr")
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmodule_3415
		and target_5.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_5.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_5.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_5.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="unknown tagname"
		and target_5.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_6(Parameter vtif_3413, AddressOfExpr target_6) {
		target_6.getOperand().(ValueFieldAccess).getTarget().getName()="td_stripoffset"
		and target_6.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
}

predicate func_7(Parameter vtif_3413, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("TIFFFetchStripThing")
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3413
		and target_7.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TIFFDirEntry *")
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="td_nstrips"
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
}

predicate func_8(Parameter vtif_3413, Variable vmodule_3415, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3413
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_3415
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Ignoring %s since BitsPerSample tag not found"
		and target_8.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_8.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_8.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_8.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="unknown tagname"
}

from Function func, Parameter vtif_3413, Variable vmodule_3415, PointerFieldAccess target_2, ExprStmt target_3, NotExpr target_4, ExprStmt target_5, AddressOfExpr target_6, NotExpr target_7, ExprStmt target_8
where
not func_0(vtif_3413, vmodule_3415, target_2, target_3, target_4, target_5)
and not func_1(vtif_3413, vmodule_3415, target_2, target_6, target_7, target_8)
and func_2(target_2)
and func_3(vtif_3413, target_3)
and func_4(vtif_3413, target_4)
and func_5(vtif_3413, vmodule_3415, target_5)
and func_6(vtif_3413, target_6)
and func_7(vtif_3413, target_7)
and func_8(vtif_3413, vmodule_3415, target_8)
and vtif_3413.getType().hasName("TIFF *")
and vmodule_3415.getType().hasName("const char[]")
and vtif_3413.getFunction() = func
and vmodule_3415.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
