/**
 * @name redis-5727d7ec2ff260b03c5aaadb2b7fb45cb6e7ef05-clusterLoadConfig
 * @id cpp/redis/5727d7ec2ff260b03c5aaadb2b7fb45cb6e7ef05/clusterLoadConfig
 * @description redis-5727d7ec2ff260b03c5aaadb2b7fb45cb6e7ef05-clusterLoadConfig CVE-2017-15047
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vslot_227, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslot_227
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslot_227
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16384"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstart_223, ExprStmt target_6, RelationalOperation target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vstart_223
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstart_223
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16384"
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vstop_223, ExprStmt target_6, RelationalOperation target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vstop_223
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstop_223
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16384"
		and target_6.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("sds *")
		and target_3.getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(CharLiteral).getValue()="91"
}

predicate func_4(Variable vslot_227, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslot_227
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("sds *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vslot_227, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="migrating_slots_to"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="cluster"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vslot_227
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("clusterNode *")
}

predicate func_6(Variable vstart_223, Variable vstop_223, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_223
		and target_6.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstop_223
		and target_6.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_6.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("sds *")
		and target_6.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_7(Variable vstart_223, Variable vstop_223, RelationalOperation target_7) {
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vstart_223
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vstop_223
}

from Function func, Variable vstart_223, Variable vstop_223, Variable vslot_227, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7
where
not func_0(vslot_227, target_3, target_4, target_5)
and not func_1(vstart_223, target_6, target_7)
and not func_2(vstop_223, target_6, target_7)
and func_3(target_3)
and func_4(vslot_227, target_4)
and func_5(vslot_227, target_5)
and func_6(vstart_223, vstop_223, target_6)
and func_7(vstart_223, vstop_223, target_7)
and vstart_223.getType().hasName("int")
and vstop_223.getType().hasName("int")
and vslot_227.getType().hasName("int")
and vstart_223.getParentScope+() = func
and vstop_223.getParentScope+() = func
and vslot_227.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
