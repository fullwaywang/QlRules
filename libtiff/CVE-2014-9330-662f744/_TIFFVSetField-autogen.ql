/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-_TIFFVSetField
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/-TIFFVSetField
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-libtiff/tif_dir.c-_TIFFVSetField CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vap_156, BuiltInVarArg target_13) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("double")
		and target_0.getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vap_156
		and target_13.getVAList().(VariableAccess).getLocation().isBefore(target_0.getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getLocation()))
}

predicate func_1(VariableAccess target_15, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("double")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_15
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Parameter vap_156, VariableAccess target_15, ExprStmt target_17) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("double")
		and target_3.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vap_156
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_15
		and target_3.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getLocation()))
}

predicate func_4(VariableAccess target_15, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("double")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_15
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vtd_160, VariableAccess target_15, ExprStmt target_18, ExprStmt target_19) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_yresolution"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_160
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("double")
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_15
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vtif_156, Variable vmodule_158, ExprStmt target_20) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_156
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_158
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: Bad value %f for \"%s\" tag"
		and target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_name"
		and target_8.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_156
		and target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("double")
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("const TIFFField *")
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const TIFFField *")
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="Unknown"
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vap_156, ExprStmt target_21) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(BuiltInVarArgsEnd).getVAList().(VariableAccess).getTarget()=vap_156
		and target_21.getExpr().(BuiltInVarArgsEnd).getVAList().(VariableAccess).getLocation().isBefore(target_9.getExpr().(BuiltInVarArgsEnd).getVAList().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vap_156, BuiltInVarArg target_11) {
		target_11.getVAList().(VariableAccess).getTarget()=vap_156
}

predicate func_12(Parameter vap_156, BuiltInVarArg target_12) {
		target_12.getVAList().(VariableAccess).getTarget()=vap_156
}

predicate func_13(Parameter vap_156, BuiltInVarArg target_13) {
		target_13.getVAList().(VariableAccess).getTarget()=vap_156
}

predicate func_15(Variable vstandard_tag_165, VariableAccess target_15) {
		target_15.getTarget()=vstandard_tag_165
}

predicate func_17(Parameter vap_156, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_17.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vap_156
}

predicate func_18(Variable vtd_160, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_xresolution"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_160
		and target_18.getExpr().(AssignExpr).getRValue() instanceof BuiltInVarArg
}

predicate func_19(Variable vtd_160, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="td_planarconfig"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_160
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_20(Parameter vtif_156, Variable vmodule_158, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_156
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_158
		and target_20.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: Bad value %u for \"%s\" tag"
		and target_20.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_name"
		and target_20.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_156
		and target_20.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_20.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_20.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="field_name"
		and target_20.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("const TIFFField *")
		and target_20.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="Unknown"
}

predicate func_21(Parameter vap_156, ExprStmt target_21) {
		target_21.getExpr().(BuiltInVarArgsEnd).getVAList().(VariableAccess).getTarget()=vap_156
}

from Function func, Parameter vtif_156, Parameter vap_156, Variable vmodule_158, Variable vtd_160, Variable vstandard_tag_165, BuiltInVarArg target_11, BuiltInVarArg target_12, BuiltInVarArg target_13, VariableAccess target_15, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21
where
not func_0(vap_156, target_13)
and not func_1(target_15, func)
and not func_3(vap_156, target_15, target_17)
and not func_4(target_15, func)
and not func_5(vtd_160, target_15, target_18, target_19)
and not func_8(vtif_156, vmodule_158, target_20)
and not func_9(vap_156, target_21)
and func_11(vap_156, target_11)
and func_12(vap_156, target_12)
and func_13(vap_156, target_13)
and func_15(vstandard_tag_165, target_15)
and func_17(vap_156, target_17)
and func_18(vtd_160, target_18)
and func_19(vtd_160, target_19)
and func_20(vtif_156, vmodule_158, target_20)
and func_21(vap_156, target_21)
and vtif_156.getType().hasName("TIFF *")
and vap_156.getType().hasName("va_list")
and vmodule_158.getType().hasName("const char[]")
and vtd_160.getType().hasName("TIFFDirectory *")
and vstandard_tag_165.getType().hasName("uint32")
and vtif_156.getFunction() = func
and vap_156.getFunction() = func
and vmodule_158.(LocalVariable).getFunction() = func
and vtd_160.(LocalVariable).getFunction() = func
and vstandard_tag_165.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
