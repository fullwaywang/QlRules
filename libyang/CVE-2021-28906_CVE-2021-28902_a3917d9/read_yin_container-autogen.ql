/**
 * @name libyang-a3917d95d516e3de267d3cfa5d4d3715a90e8777-read_yin_container
 * @id cpp/libyang/a3917d95d516e3de267d3cfa5d4d3715a90e8777/read-yin-container
 * @description libyang-a3917d95d516e3de267d3cfa5d4d3715a90e8777-src/parser_yin.c-read_yin_container CVE-2021-28902
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vretval_5512, Variable vr_5516, BlockStmt target_2, RelationalOperation target_3, ArrayExpr target_4, PrefixIncrExpr target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ext"
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vr_5516
		and target_0.getAnOperand() instanceof BitwiseAndExpr
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vretval_5512, Variable vr_5516, BlockStmt target_2, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ext"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vr_5516
		and target_1.getRightOperand().(Literal).getValue()="8"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vretval_5512, Variable vr_5516, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8192"
		and target_2.getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ext"
		and target_2.getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_2.getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vr_5516
		and target_2.getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16384"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
}

predicate func_3(Variable vretval_5512, Variable vr_5516, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vr_5516
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ext_size"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
}

predicate func_4(Variable vretval_5512, Variable vr_5516, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="ext"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vretval_5512
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vr_5516
}

predicate func_5(Variable vr_5516, PrefixIncrExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vr_5516
}

from Function func, Variable vretval_5512, Variable vr_5516, BitwiseAndExpr target_1, BlockStmt target_2, RelationalOperation target_3, ArrayExpr target_4, PrefixIncrExpr target_5
where
not func_0(vretval_5512, vr_5516, target_2, target_3, target_4, target_5)
and func_1(vretval_5512, vr_5516, target_2, target_1)
and func_2(vretval_5512, vr_5516, target_2)
and func_3(vretval_5512, vr_5516, target_3)
and func_4(vretval_5512, vr_5516, target_4)
and func_5(vr_5516, target_5)
and vretval_5512.getType().hasName("lys_node *")
and vr_5516.getType().hasName("int")
and vretval_5512.getParentScope+() = func
and vr_5516.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
