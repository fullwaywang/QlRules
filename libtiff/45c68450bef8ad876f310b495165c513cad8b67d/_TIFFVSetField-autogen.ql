/**
 * @name libtiff-45c68450bef8ad876f310b495165c513cad8b67d-_TIFFVSetField
 * @id cpp/libtiff/45c68450bef8ad876f310b495165c513cad8b67d/-TIFFVSetField
 * @description libtiff-45c68450bef8ad876f310b495165c513cad8b67d-libtiff/tif_dir.c-_TIFFVSetField CVE-2016-3658
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_160, Variable vtd_162, Variable vv_164, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vv_164
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_162
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_sminsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_162
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_160
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SamplesPerPixel tag value is changing, but SMinSampleValue tag was read with a different value. Cancelling it"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="td_sminsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_sminsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_smaxsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_162
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFWarningExt")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_160
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SamplesPerPixel tag value is changing, but SMaxSampleValue tag was read with a different value. Cancelling it"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="td_smaxsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_smaxsamplevalue"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstandard_tag_168, VariableAccess target_1) {
		target_1.getTarget()=vstandard_tag_168
}

predicate func_2(Variable vmodule_160, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_160
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: Sorry, cannot nest SubIFDs"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_name"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TIFF *")
}

predicate func_3(Variable vtd_162, Variable vv_164, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_orientation"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_162
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vv_164
}

predicate func_4(Variable vv_164, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vv_164
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vtd_162, Variable vv_164, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_162
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vv_164
}

from Function func, Variable vmodule_160, Variable vtd_162, Variable vv_164, Variable vstandard_tag_168, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5
where
not func_0(vmodule_160, vtd_162, vv_164, target_1, target_2, target_3, target_4, target_5)
and func_1(vstandard_tag_168, target_1)
and func_2(vmodule_160, target_2)
and func_3(vtd_162, vv_164, target_3)
and func_4(vv_164, target_4)
and func_5(vtd_162, vv_164, target_5)
and vmodule_160.getType().hasName("const char[]")
and vtd_162.getType().hasName("TIFFDirectory *")
and vv_164.getType().hasName("uint32")
and vstandard_tag_168.getType().hasName("uint32")
and vmodule_160.(LocalVariable).getFunction() = func
and vtd_162.(LocalVariable).getFunction() = func
and vv_164.(LocalVariable).getFunction() = func
and vstandard_tag_168.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
