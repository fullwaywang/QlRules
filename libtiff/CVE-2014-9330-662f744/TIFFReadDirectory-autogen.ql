/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-TIFFReadDirectory
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/TIFFReadDirectory
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-libtiff/tif_dirread.c-TIFFReadDirectory CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdp_3428, NotExpr target_5, EqualityOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="258"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdp_3428, Variable vfip_3430, Parameter vtif_3423, Variable vmodule_3425, NotExpr target_7, LogicalAndExpr target_8, ConditionalExpr target_9, AddressOfExpr target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfip_3430
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFFieldWithTag")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3423
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_3425
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Ignoring %s since BitsPerSample tag not found"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vfip_3430
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_3430
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="unknown tagname"
		and target_7.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getCondition().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Function func, LabelStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vdp_3428, Parameter vtif_3423, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3423
		and target_5.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_5.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_5.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint16")
}

predicate func_6(Variable vdp_3428, Parameter vtif_3423, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
}

predicate func_7(Variable vdp_3428, Parameter vtif_3423, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("TIFFFetchStripThing")
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3423
		and target_7.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdp_3428
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="td_nstrips"
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_7.getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_7.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
}

predicate func_8(Variable vdp_3428, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="301"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_3428
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_9(Variable vfip_3430, ConditionalExpr target_9) {
		target_9.getCondition().(VariableAccess).getTarget()=vfip_3430
		and target_9.getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_9.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_3430
		and target_9.getElse().(StringLiteral).getValue()="unknown tagname"
}

predicate func_10(Parameter vtif_3423, AddressOfExpr target_10) {
		target_10.getOperand().(ValueFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_10.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_10.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
}

predicate func_11(Parameter vtif_3423, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_11.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_11.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="td_bitspersample"
		and target_11.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_11.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_3423
}

predicate func_12(Variable vfip_3430, Parameter vtif_3423, Variable vmodule_3425, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("TIFFReadDirEntryOutputErr")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3423
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TIFFReadDirEntryErr")
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmodule_3425
		and target_12.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vfip_3430
		and target_12.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_12.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_3430
		and target_12.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="unknown tagname"
		and target_12.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_13(Variable vfip_3430, Parameter vtif_3423, Variable vmodule_3425, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("TIFFReadDirEntryOutputErr")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_3423
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TIFFReadDirEntryErr")
		and target_13.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmodule_3425
		and target_13.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vfip_3430
		and target_13.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_13.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_3430
		and target_13.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="unknown tagname"
		and target_13.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1"
}

from Function func, Variable vdp_3428, Variable vfip_3430, Parameter vtif_3423, Variable vmodule_3425, LabelStmt target_4, NotExpr target_5, EqualityOperation target_6, NotExpr target_7, LogicalAndExpr target_8, ConditionalExpr target_9, AddressOfExpr target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vdp_3428, target_5, target_6)
and not func_1(vdp_3428, vfip_3430, vtif_3423, vmodule_3425, target_7, target_8, target_9, target_10, target_11, target_12, target_13)
and func_4(func, target_4)
and func_5(vdp_3428, vtif_3423, target_5)
and func_6(vdp_3428, vtif_3423, target_6)
and func_7(vdp_3428, vtif_3423, target_7)
and func_8(vdp_3428, target_8)
and func_9(vfip_3430, target_9)
and func_10(vtif_3423, target_10)
and func_11(vtif_3423, target_11)
and func_12(vfip_3430, vtif_3423, vmodule_3425, target_12)
and func_13(vfip_3430, vtif_3423, vmodule_3425, target_13)
and vdp_3428.getType().hasName("TIFFDirEntry *")
and vfip_3430.getType().hasName("const TIFFField *")
and vtif_3423.getType().hasName("TIFF *")
and vmodule_3425.getType().hasName("const char[]")
and vdp_3428.(LocalVariable).getFunction() = func
and vfip_3430.(LocalVariable).getFunction() = func
and vtif_3423.getFunction() = func
and vmodule_3425.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
