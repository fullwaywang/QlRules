/**
 * @name openjpeg-cab352e249ed3372dd9355c85e837613fff98fa2-imagetopnm
 * @id cpp/openjpeg/cab352e249ed3372dd9355c85e837613fff98fa2/imagetopnm
 * @description openjpeg-cab352e249ed3372dd9355c85e837613fff98fa2-src/bin/jp2/convert.c-imagetopnm CVE-2018-18088
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vred_2021, Variable vfdest_2028, ExprStmt target_14, ExprStmt target_15) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vred_2021
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
		and target_0.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter voutfile_2019, Variable vcompno_2024, Variable vncomp_2024, Variable vdestname_2030, Variable vdotpos_2213, IfStmt target_2) {
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vncomp_2024
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdestname_2030
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voutfile_2019
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdotpos_2213
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdestname_2030
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdotpos_2213
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="_%u.pgm"
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcompno_2024
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdestname_2030
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voutfile_2019
}

predicate func_3(Variable vfdest_2028, Variable vdestname_2030, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfdest_2028
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fopen")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdestname_2030
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="wb"
}

predicate func_4(Variable vfdest_2028, Variable vdestname_2030, Variable vstderr, IfStmt target_4) {
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vfdest_2028
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ERROR -> failed to open %s for writing\n"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdestname_2030
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdestname_2030
		and target_4.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_5(Variable vwr_2022, Variable vcompno_2024, Parameter vimage_2019, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwr_2022
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="w"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2019
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_2024
}

predicate func_6(Variable vhr_2022, Variable vcompno_2024, Parameter vimage_2019, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhr_2022
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="h"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2019
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_2024
}

predicate func_7(Variable vcompno_2024, Variable vprec_2027, Parameter vimage_2019, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprec_2027
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="prec"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2019
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_2024
}

predicate func_8(Variable vmax_2022, Variable vprec_2027, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_2022
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vprec_2027
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_9(Variable vwr_2022, Variable vhr_2022, Variable vmax_2022, Variable vfdest_2028, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
		and target_9.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="P5\n#OpenJPEG-%s\n%d %d\n%d\n"
		and target_9.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("opj_version")
		and target_9.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vwr_2022
		and target_9.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhr_2022
		and target_9.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmax_2022
}

predicate func_10(Variable vred_2021, Variable vcompno_2024, Parameter vimage_2019, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vred_2021
		and target_10.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_10.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_10.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2019
		and target_10.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_2024
}

predicate func_11(Variable vcompno_2024, Variable vadjustR_2025, Parameter vimage_2019, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vadjustR_2025
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="sgnd"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2019
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcompno_2024
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="prec"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_12(Variable vred_2021, Variable vwr_2022, Variable vhr_2022, Variable vi_2023, Variable vhas_alpha_2026, Variable vprec_2027, Variable vv_2027, Variable vfdest_2028, IfStmt target_12) {
		target_12.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vprec_2027
		and target_12.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2023
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_2023
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwr_2022
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vhr_2022
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_2023
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_2027
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vred_2021
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vv_2027
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="65535"
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%c%c"
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vv_2027
		and target_12.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(VariableAccess).getTarget()=vhas_alpha_2026
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2023
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_2023
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwr_2022
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vhr_2022
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_2023
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_2027
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vred_2021
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vv_2027
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%c"
		and target_12.getElse().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vv_2027
}

predicate func_13(Variable vfdest_2028, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
}

predicate func_14(Variable vred_2021, Variable vv_2027, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_2027
		and target_14.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vred_2021
}

predicate func_15(Variable vfdest_2028, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfdest_2028
}

from Function func, Parameter voutfile_2019, Variable vred_2021, Variable vwr_2022, Variable vhr_2022, Variable vmax_2022, Variable vi_2023, Variable vcompno_2024, Variable vncomp_2024, Variable vadjustR_2025, Variable vhas_alpha_2026, Variable vprec_2027, Variable vv_2027, Parameter vimage_2019, Variable vfdest_2028, Variable vdestname_2030, Variable vstderr, Variable vdotpos_2213, IfStmt target_2, ExprStmt target_3, IfStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, IfStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15
where
not func_0(vred_2021, vfdest_2028, target_14, target_15)
and func_2(voutfile_2019, vcompno_2024, vncomp_2024, vdestname_2030, vdotpos_2213, target_2)
and func_3(vfdest_2028, vdestname_2030, target_3)
and func_4(vfdest_2028, vdestname_2030, vstderr, target_4)
and func_5(vwr_2022, vcompno_2024, vimage_2019, target_5)
and func_6(vhr_2022, vcompno_2024, vimage_2019, target_6)
and func_7(vcompno_2024, vprec_2027, vimage_2019, target_7)
and func_8(vmax_2022, vprec_2027, target_8)
and func_9(vwr_2022, vhr_2022, vmax_2022, vfdest_2028, target_9)
and func_10(vred_2021, vcompno_2024, vimage_2019, target_10)
and func_11(vcompno_2024, vadjustR_2025, vimage_2019, target_11)
and func_12(vred_2021, vwr_2022, vhr_2022, vi_2023, vhas_alpha_2026, vprec_2027, vv_2027, vfdest_2028, target_12)
and func_13(vfdest_2028, target_13)
and func_14(vred_2021, vv_2027, target_14)
and func_15(vfdest_2028, target_15)
and voutfile_2019.getType().hasName("const char *")
and vred_2021.getType().hasName("int *")
and vwr_2022.getType().hasName("int")
and vhr_2022.getType().hasName("int")
and vmax_2022.getType().hasName("int")
and vi_2023.getType().hasName("int")
and vcompno_2024.getType().hasName("unsigned int")
and vncomp_2024.getType().hasName("unsigned int")
and vadjustR_2025.getType().hasName("int")
and vhas_alpha_2026.getType().hasName("int")
and vprec_2027.getType().hasName("int")
and vv_2027.getType().hasName("int")
and vimage_2019.getType().hasName("opj_image_t *")
and vfdest_2028.getType().hasName("FILE *")
and vdestname_2030.getType().hasName("char *")
and vstderr.getType().hasName("FILE *")
and vdotpos_2213.getType().hasName("const size_t")
and voutfile_2019.getParentScope+() = func
and vred_2021.getParentScope+() = func
and vwr_2022.getParentScope+() = func
and vhr_2022.getParentScope+() = func
and vmax_2022.getParentScope+() = func
and vi_2023.getParentScope+() = func
and vcompno_2024.getParentScope+() = func
and vncomp_2024.getParentScope+() = func
and vadjustR_2025.getParentScope+() = func
and vhas_alpha_2026.getParentScope+() = func
and vprec_2027.getParentScope+() = func
and vv_2027.getParentScope+() = func
and vimage_2019.getParentScope+() = func
and vfdest_2028.getParentScope+() = func
and vdestname_2030.getParentScope+() = func
and not vstderr.getParentScope+() = func
and vdotpos_2213.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
