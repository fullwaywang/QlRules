/**
 * @name libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlCreateEntity
 * @id cpp/libxml2/1b41ec4e9433b05bb0376be4725804c54ef1d80b/xmlCreateEntity
 * @description libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-entities.c-xmlCreateEntity CVE-2022-40304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vExternalID_171, ExprStmt target_17) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlStrdup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vExternalID_171
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vSystemID_171, ExprStmt target_19, ExprStmt target_12) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xmlStrdup")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vSystemID_171
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcontent_172, BlockStmt target_20, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vcontent_172
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_20
}

predicate func_3(Variable vret_173, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="content"
		and target_3.getQualifier().(VariableAccess).getTarget()=vret_173
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Variable vret_173, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="length"
		and target_4.getQualifier().(VariableAccess).getTarget()=vret_173
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Parameter vcontent_172, Variable vret_173, LogicalAndExpr target_21, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrndup")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontent_172
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_5.getParent().(IfStmt).getCondition()=target_21
}

predicate func_6(Variable vret_173, EqualityOperation target_2, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getCondition()=target_2
}

predicate func_7(Parameter vExternalID_171, ExprStmt target_22, VariableAccess target_7) {
		target_7.getTarget()=vExternalID_171
		and target_7.getParent().(NEExpr).getAnOperand() instanceof Literal
		and target_7.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_22
}

predicate func_8(Parameter vSystemID_171, ExprStmt target_12, VariableAccess target_8) {
		target_8.getTarget()=vSystemID_171
		and target_8.getParent().(NEExpr).getAnOperand() instanceof Literal
		and target_8.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_9(Parameter vdict_170, Parameter vExternalID_171, Variable vret_173, EqualityOperation target_23, IfStmt target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vExternalID_171
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vExternalID_171
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

/*predicate func_10(Parameter vdict_170, Parameter vExternalID_171, FunctionCall target_10) {
		target_10.getTarget().hasName("xmlDictLookup")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_10.getArgument(1).(VariableAccess).getTarget()=vExternalID_171
		and target_10.getArgument(2).(UnaryMinusExpr).getValue()="-1"
}

*/
predicate func_11(Parameter vSystemID_171, ExprStmt target_12, ExprStmt target_19, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vSystemID_171
		and target_11.getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen()=target_12
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation())
}

predicate func_12(Parameter vdict_170, Parameter vSystemID_171, Variable vret_173, EqualityOperation target_11, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vSystemID_171
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_12.getParent().(IfStmt).getCondition()=target_11
}

/*predicate func_13(Parameter vdict_170, Parameter vSystemID_171, FunctionCall target_13) {
		target_13.getTarget().hasName("xmlDictLookup")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_13.getArgument(1).(VariableAccess).getTarget()=vSystemID_171
		and target_13.getArgument(2).(UnaryMinusExpr).getValue()="-1"
}

*/
predicate func_14(Parameter vdict_170, Parameter vcontent_172, Variable vret_173, Function func, IfStmt target_14) {
		target_14.getCondition() instanceof EqualityOperation
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontent_172
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_170
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcontent_172
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse() instanceof ExprStmt
		and target_14.getElse() instanceof BlockStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

/*predicate func_15(Parameter vdict_170, Parameter vcontent_172, Variable vret_173, EqualityOperation target_2, IfStmt target_15) {
		target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_170
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcontent_172
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_15.getElse() instanceof ExprStmt
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
/*predicate func_16(Parameter vdict_170, Parameter vcontent_172, Variable vret_173, AssignExpr target_16) {
		target_16.getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_16.getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_16.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_16.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcontent_172
		and target_16.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_16.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
}

*/
predicate func_17(Parameter vExternalID_171, Variable vret_173, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vExternalID_171
}

predicate func_19(Parameter vSystemID_171, Variable vret_173, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrdup")
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vSystemID_171
}

predicate func_20(Parameter vcontent_172, Variable vret_173, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontent_172
		and target_20.getStmt(1) instanceof IfStmt
}

predicate func_21(LogicalAndExpr target_21) {
		target_21.getAnOperand() instanceof EqualityOperation
		and target_21.getAnOperand() instanceof RelationalOperation
}

predicate func_22(Variable vret_173, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_22.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_23(Parameter vdict_170, EqualityOperation target_23) {
		target_23.getAnOperand().(VariableAccess).getTarget()=vdict_170
		and target_23.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdict_170, Parameter vExternalID_171, Parameter vSystemID_171, Parameter vcontent_172, Variable vret_173, EqualityOperation target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, ExprStmt target_5, BlockStmt target_6, VariableAccess target_7, VariableAccess target_8, IfStmt target_9, EqualityOperation target_11, ExprStmt target_12, IfStmt target_14, ExprStmt target_17, ExprStmt target_19, BlockStmt target_20, LogicalAndExpr target_21, ExprStmt target_22, EqualityOperation target_23
where
not func_0(vExternalID_171, target_17)
and not func_1(vSystemID_171, target_19, target_12)
and func_2(vcontent_172, target_20, target_2)
and func_3(vret_173, target_3)
and func_4(vret_173, target_4)
and func_5(vcontent_172, vret_173, target_21, target_5)
and func_6(vret_173, target_2, target_6)
and func_7(vExternalID_171, target_22, target_7)
and func_8(vSystemID_171, target_12, target_8)
and func_9(vdict_170, vExternalID_171, vret_173, target_23, target_9)
and func_11(vSystemID_171, target_12, target_19, target_11)
and func_12(vdict_170, vSystemID_171, vret_173, target_11, target_12)
and func_14(vdict_170, vcontent_172, vret_173, func, target_14)
and func_17(vExternalID_171, vret_173, target_17)
and func_19(vSystemID_171, vret_173, target_19)
and func_20(vcontent_172, vret_173, target_20)
and func_21(target_21)
and func_22(vret_173, target_22)
and func_23(vdict_170, target_23)
and vdict_170.getType().hasName("xmlDictPtr")
and vExternalID_171.getType().hasName("const xmlChar *")
and vSystemID_171.getType().hasName("const xmlChar *")
and vcontent_172.getType().hasName("const xmlChar *")
and vret_173.getType().hasName("xmlEntityPtr")
and vdict_170.getParentScope+() = func
and vExternalID_171.getParentScope+() = func
and vSystemID_171.getParentScope+() = func
and vcontent_172.getParentScope+() = func
and vret_173.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
