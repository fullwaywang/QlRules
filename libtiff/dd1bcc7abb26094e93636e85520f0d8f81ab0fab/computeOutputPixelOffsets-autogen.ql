/**
 * @name libtiff-dd1bcc7abb26094e93636e85520f0d8f81ab0fab-computeOutputPixelOffsets
 * @id cpp/libtiff/dd1bcc7abb26094e93636e85520f0d8f81ab0fab/computeOutputPixelOffsets
 * @description libtiff-dd1bcc7abb26094e93636e85520f0d8f81ab0fab-tools/tiffcrop.c-computeOutputPixelOffsets CVE-2022-2056
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhmargin_5798) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_0.getArgument(0) instanceof MulExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhmargin_5798)
}

predicate func_1(Variable vvmargin_5798) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_1.getArgument(0) instanceof MulExpr
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvmargin_5798)
}

predicate func_2(Variable vhmargin_5798) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_2.getArgument(0) instanceof MulExpr
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhmargin_5798)
}

predicate func_3(Variable vvmargin_5798) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_3.getArgument(0) instanceof MulExpr
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvmargin_5798)
}

predicate func_4(Variable vowidth_5796) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_4.getArgument(0) instanceof SubExpr
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vowidth_5796)
}

predicate func_5(Variable volength_5796) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_5.getArgument(0) instanceof SubExpr
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=volength_5796)
}

predicate func_6(Variable vowidth_5796) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_6.getArgument(0) instanceof SubExpr
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vowidth_5796)
}

predicate func_7(Variable volength_5796) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_7.getArgument(0) instanceof SubExpr
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=volength_5796)
}

predicate func_8(Variable vowidth_5796, Variable volength_5796, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vowidth_5796
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=volength_5796
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="computeOutputPixelOffsets"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating the number of pages"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_8)
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vimage_5789, Parameter vpage_5790, Variable vscale_5793, Variable vhmargin_5798, MulExpr target_9) {
		target_9.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="hmargin"
		and target_9.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_9.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5793
		and target_9.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="hres"
		and target_9.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bps"
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5789
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_9.getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhmargin_5798
}

predicate func_10(Parameter vimage_5789, Parameter vpage_5790, Variable vscale_5793, Variable vvmargin_5798, MulExpr target_10) {
		target_10.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vmargin"
		and target_10.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_10.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5793
		and target_10.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="vres"
		and target_10.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_10.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bps"
		and target_10.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5789
		and target_10.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_10.getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvmargin_5798
}

predicate func_11(Parameter vimage_5789, Parameter vpage_5790, Variable vscale_5793, Variable vhmargin_5798, MulExpr target_11) {
		target_11.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="hmargin"
		and target_11.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_11.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5793
		and target_11.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bps"
		and target_11.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5789
		and target_11.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_11.getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhmargin_5798
}

predicate func_12(Parameter vimage_5789, Parameter vpage_5790, Variable vscale_5793, Variable vvmargin_5798, MulExpr target_12) {
		target_12.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vmargin"
		and target_12.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_12.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5793
		and target_12.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bps"
		and target_12.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5789
		and target_12.getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_12.getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvmargin_5798
}

predicate func_13(Parameter vpage_5790, Variable vpwidth_5794, Variable vowidth_5796, Variable vhmargin_5798, SubExpr target_13) {
		target_13.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vpwidth_5794
		and target_13.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="hres"
		and target_13.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_13.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vhmargin_5798
		and target_13.getRightOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vowidth_5796
}

predicate func_14(Parameter vpage_5790, Variable vplength_5794, Variable volength_5796, Variable vvmargin_5798, SubExpr target_14) {
		target_14.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vplength_5794
		and target_14.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="vres"
		and target_14.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_14.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vvmargin_5798
		and target_14.getRightOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_14.getParent().(AssignExpr).getRValue() = target_14
		and target_14.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=volength_5796
}

predicate func_15(Parameter vpage_5790, Variable viwidth_5795, Variable vowidth_5796, Variable vhmargin_5798, SubExpr target_15) {
		target_15.getLeftOperand().(VariableAccess).getTarget()=viwidth_5795
		and target_15.getRightOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vhmargin_5798
		and target_15.getRightOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_15.getRightOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="hres"
		and target_15.getRightOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vowidth_5796
}

predicate func_16(Parameter vpage_5790, Variable vilength_5795, Variable volength_5796, Variable vvmargin_5798, SubExpr target_16) {
		target_16.getLeftOperand().(VariableAccess).getTarget()=vilength_5795
		and target_16.getRightOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vvmargin_5798
		and target_16.getRightOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_16.getRightOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="vres"
		and target_16.getRightOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_5790
		and target_16.getParent().(AssignExpr).getRValue() = target_16
		and target_16.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=volength_5796
}

predicate func_17(Variable viwidth_5795, Variable vowidth_5796, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vowidth_5796
		and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=viwidth_5795
}

predicate func_18(Variable viwidth_5795, Variable vowidth_5796, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_18.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=viwidth_5795
		and target_18.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vowidth_5796
		and target_18.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_18.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vowidth_5796
}

predicate func_19(Variable vilength_5795, Variable volength_5796, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=volength_5796
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vilength_5795
}

predicate func_20(Variable vilength_5795, Variable volength_5796, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vilength_5795
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=volength_5796
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_20.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=volength_5796
}

from Function func, Parameter vimage_5789, Parameter vpage_5790, Variable vscale_5793, Variable vpwidth_5794, Variable vplength_5794, Variable viwidth_5795, Variable vilength_5795, Variable vowidth_5796, Variable volength_5796, Variable vhmargin_5798, Variable vvmargin_5798, MulExpr target_9, MulExpr target_10, MulExpr target_11, MulExpr target_12, SubExpr target_13, SubExpr target_14, SubExpr target_15, SubExpr target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20
where
not func_0(vhmargin_5798)
and not func_1(vvmargin_5798)
and not func_2(vhmargin_5798)
and not func_3(vvmargin_5798)
and not func_4(vowidth_5796)
and not func_5(volength_5796)
and not func_6(vowidth_5796)
and not func_7(volength_5796)
and not func_8(vowidth_5796, volength_5796, target_17, target_18, target_19, target_20, func)
and func_9(vimage_5789, vpage_5790, vscale_5793, vhmargin_5798, target_9)
and func_10(vimage_5789, vpage_5790, vscale_5793, vvmargin_5798, target_10)
and func_11(vimage_5789, vpage_5790, vscale_5793, vhmargin_5798, target_11)
and func_12(vimage_5789, vpage_5790, vscale_5793, vvmargin_5798, target_12)
and func_13(vpage_5790, vpwidth_5794, vowidth_5796, vhmargin_5798, target_13)
and func_14(vpage_5790, vplength_5794, volength_5796, vvmargin_5798, target_14)
and func_15(vpage_5790, viwidth_5795, vowidth_5796, vhmargin_5798, target_15)
and func_16(vpage_5790, vilength_5795, volength_5796, vvmargin_5798, target_16)
and func_17(viwidth_5795, vowidth_5796, target_17)
and func_18(viwidth_5795, vowidth_5796, target_18)
and func_19(vilength_5795, volength_5796, target_19)
and func_20(vilength_5795, volength_5796, target_20)
and vimage_5789.getType().hasName("image_data *")
and vpage_5790.getType().hasName("pagedef *")
and vscale_5793.getType().hasName("double")
and vpwidth_5794.getType().hasName("double")
and vplength_5794.getType().hasName("double")
and viwidth_5795.getType().hasName("uint32_t")
and vilength_5795.getType().hasName("uint32_t")
and vowidth_5796.getType().hasName("uint32_t")
and volength_5796.getType().hasName("uint32_t")
and vhmargin_5798.getType().hasName("uint32_t")
and vvmargin_5798.getType().hasName("uint32_t")
and vimage_5789.getFunction() = func
and vpage_5790.getFunction() = func
and vscale_5793.(LocalVariable).getFunction() = func
and vpwidth_5794.(LocalVariable).getFunction() = func
and vplength_5794.(LocalVariable).getFunction() = func
and viwidth_5795.(LocalVariable).getFunction() = func
and vilength_5795.(LocalVariable).getFunction() = func
and vowidth_5796.(LocalVariable).getFunction() = func
and volength_5796.(LocalVariable).getFunction() = func
and vhmargin_5798.(LocalVariable).getFunction() = func
and vvmargin_5798.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
