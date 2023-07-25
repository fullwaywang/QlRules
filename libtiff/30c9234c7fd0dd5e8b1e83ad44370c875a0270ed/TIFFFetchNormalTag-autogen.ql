/**
 * @name libtiff-30c9234c7fd0dd5e8b1e83ad44370c875a0270ed-TIFFFetchNormalTag
 * @id cpp/libtiff/30c9234c7fd0dd5e8b1e83ad44370c875a0270ed/TIFFFetchNormalTag
 * @description libtiff-30c9234c7fd0dd5e8b1e83ad44370c875a0270ed-libtiff/tif_dirread.c-TIFFFetchNormalTag CVE-2016-9297
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtif_4713, Parameter vdp_4713, Variable vmodule_4715, Variable vfip_4718, Variable vdata_5185, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ConditionalExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_5185
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_4713
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_4715
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ASCII value for tag \"%s\" does not end in null byte. Forcing it to be null"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="field_name"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_4718
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_5185
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtif_4713, Parameter vdp_4713, Variable vmodule_4715, Variable verr_4716, Variable vdata_5185, ExprStmt target_7, ExprStmt target_8, EqualityOperation target_3, AddressOfExpr target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_4716
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_5185
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_4715
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ASCII value for tag \"%s\" does not end in null byte. Forcing it to be null"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="field_name"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_4713
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_5185
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_5185
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_5185
		and target_1.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtif_4713, Parameter vdp_4713, Variable verr_4716, Variable vdata_5014, Variable vm_5024, RelationalOperation target_10, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_4716
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vm_5024
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_4713
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_5014
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_5014
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_5014
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vm_5024
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_3(Variable verr_4716, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=verr_4716
}

predicate func_4(Parameter vtif_4713, Parameter vdp_4713, Variable vdata_5185, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_4713
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_5185
}

predicate func_5(Parameter vtif_4713, Variable vmodule_4715, Variable verr_4716, Variable vfip_4718, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("TIFFReadDirEntryOutputErr")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_4713
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=verr_4716
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmodule_4715
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="field_name"
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_4718
		and target_5.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_6(Variable vfip_4718, ConditionalExpr target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="field_readcount"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_4718
		and target_6.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-3"
		and target_6.getThen() instanceof Literal
		and target_6.getElse() instanceof Literal
}

predicate func_7(Parameter vtif_4713, Parameter vdp_4713, Variable vmodule_4715, Variable vfip_4718, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_4713
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_4715
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="incorrect count for field \"%s\", expected %d, got %d"
		and target_7.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="field_name"
		and target_7.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_4718
		and target_7.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="field_readcount"
		and target_7.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfip_4718
		and target_7.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_7.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
}

predicate func_8(Parameter vtif_4713, Parameter vdp_4713, Variable verr_4716, Variable vdata_5185, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_4716
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadDirEntryByteArray")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_4713
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdp_4713
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdata_5185
}

predicate func_9(Variable vdata_5185, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vdata_5185
}

predicate func_10(Parameter vdp_4713, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4713
		and target_10.getLesserOperand().(HexLiteral).getValue()="65535"
}

from Function func, Parameter vtif_4713, Parameter vdp_4713, Variable vmodule_4715, Variable verr_4716, Variable vfip_4718, Variable vdata_5014, Variable vm_5024, Variable vdata_5185, IfStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ConditionalExpr target_6, ExprStmt target_7, ExprStmt target_8, AddressOfExpr target_9, RelationalOperation target_10
where
not func_0(vtif_4713, vdp_4713, vmodule_4715, vfip_4718, vdata_5185, target_3, target_4, target_5, target_6)
and not func_1(vtif_4713, vdp_4713, vmodule_4715, verr_4716, vdata_5185, target_7, target_8, target_3, target_9)
and func_2(vtif_4713, vdp_4713, verr_4716, vdata_5014, vm_5024, target_10, target_2)
and func_3(verr_4716, target_3)
and func_4(vtif_4713, vdp_4713, vdata_5185, target_4)
and func_5(vtif_4713, vmodule_4715, verr_4716, vfip_4718, target_5)
and func_6(vfip_4718, target_6)
and func_7(vtif_4713, vdp_4713, vmodule_4715, vfip_4718, target_7)
and func_8(vtif_4713, vdp_4713, verr_4716, vdata_5185, target_8)
and func_9(vdata_5185, target_9)
and func_10(vdp_4713, target_10)
and vtif_4713.getType().hasName("TIFF *")
and vdp_4713.getType().hasName("TIFFDirEntry *")
and vmodule_4715.getType().hasName("const char[]")
and verr_4716.getType().hasName("TIFFReadDirEntryErr")
and vfip_4718.getType().hasName("const TIFFField *")
and vdata_5014.getType().hasName("uint8 *")
and vm_5024.getType().hasName("int")
and vdata_5185.getType().hasName("uint8 *")
and vtif_4713.getFunction() = func
and vdp_4713.getFunction() = func
and vmodule_4715.(LocalVariable).getFunction() = func
and verr_4716.(LocalVariable).getFunction() = func
and vfip_4718.(LocalVariable).getFunction() = func
and vdata_5014.(LocalVariable).getFunction() = func
and vm_5024.(LocalVariable).getFunction() = func
and vdata_5185.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
