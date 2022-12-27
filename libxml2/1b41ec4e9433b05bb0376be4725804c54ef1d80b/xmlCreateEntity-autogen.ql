/**
 * @name libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlCreateEntity
 * @id cpp/libxml2/1b41ec4e9433b05bb0376be4725804c54ef1d80b/xmlCreateEntity
 * @description libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlCreateEntity CVE-2022-40304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vret_173) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="length"
		and target_3.getQualifier().(VariableAccess).getTarget()=vret_173)
}

predicate func_4(Variable vret_173) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="content"
		and target_4.getQualifier().(VariableAccess).getTarget()=vret_173
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_5(Parameter vcontent_172, Variable vret_173) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrndup")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontent_172
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_5.getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

predicate func_6(Parameter vcontent_172, Variable vret_173) {
	exists(BlockStmt target_6 |
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcontent_172
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_9(Parameter vdict_170, Parameter vExternalID_171, Variable vret_173) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vExternalID_171
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vExternalID_171
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_170
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_14(Parameter vdict_170, Parameter vcontent_172, Variable vret_173, Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition() instanceof EqualityOperation
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontent_172
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_170
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerFieldAccess
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_170
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcontent_172
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_173
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse() instanceof ExprStmt
		and target_14.getElse() instanceof BlockStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

from Function func, Parameter vdict_170, Parameter vExternalID_171, Parameter vSystemID_171, Parameter vcontent_172, Variable vret_173
where
func_3(vret_173)
and func_4(vret_173)
and func_5(vcontent_172, vret_173)
and func_6(vcontent_172, vret_173)
and func_9(vdict_170, vExternalID_171, vret_173)
and func_14(vdict_170, vcontent_172, vret_173, func)
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
