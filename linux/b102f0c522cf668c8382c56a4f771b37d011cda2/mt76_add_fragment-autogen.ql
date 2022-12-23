/**
 * @name linux-b102f0c522cf668c8382c56a4f771b37d011cda2-mt76_add_fragment
 * @id cpp/linux/b102f0c522cf668c8382c56a4f771b37d011cda2/mt76_add_fragment
 * @description linux-b102f0c522cf668c8382c56a4f771b37d011cda2-mt76_add_fragment 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_0)
}

predicate func_1(Parameter vq_444, Parameter vlen_445, Variable vpage_447, Variable voffset_448, Variable vskb_449, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="nr_frags"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skb_shared_info *")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="17"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getValue()="17"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="frags"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skb_shared_info *")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="frags"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skb_shared_info *")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("skb_add_rx_frag")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_449
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="nr_frags"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skb_shared_info *")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpage_447
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_448
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vlen_445
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="buf_size"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_444
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vq_444, Variable voffset_448, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_448
		and target_3.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="buf_offset"
		and target_3.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_444
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vskb_449) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("skb_end_pointer")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vskb_449)
}

from Function func, Parameter vq_444, Parameter vlen_445, Variable vpage_447, Variable voffset_448, Variable vskb_449
where
not func_0(func)
and not func_1(vq_444, vlen_445, vpage_447, voffset_448, vskb_449, func)
and func_3(vq_444, voffset_448, func)
and func_4(vskb_449)
and vq_444.getType().hasName("mt76_queue *")
and vlen_445.getType().hasName("int")
and vpage_447.getType().hasName("page *")
and voffset_448.getType().hasName("int")
and vskb_449.getType().hasName("sk_buff *")
and vq_444.getParentScope+() = func
and vlen_445.getParentScope+() = func
and vpage_447.getParentScope+() = func
and voffset_448.getParentScope+() = func
and vskb_449.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
