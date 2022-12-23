/**
 * @name linux-b71812168571fa55e44cdd0254471331b9c4c4c6-size_entry_mwt
 * @id cpp/linux/b71812168571fa55e44cdd0254471331b9c4c4c6/size-entry-mwt
 * @description linux-b71812168571fa55e44cdd0254471331b9c4c4c6-size_entry_mwt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtotal_2072, Variable vi_2075, Variable voffsets_2077, Function func) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2075
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_2075
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_2075
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voffsets_2077
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2075
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtotal_2072
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_2075
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voffsets_2077
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_2075
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voffsets_2077
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2075
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getStmt().(BlockStmt).getStmt(3).(LabelStmt).toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0))
}

predicate func_5(Parameter vtotal_2072, Variable vstartoff_2075, Variable v__ret_warn_on_2150) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_5.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtotal_2072
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstartoff_2075
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=v__ret_warn_on_2150
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_5.getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="375")
}

predicate func_6(Parameter vtotal_2072) {
	exists(PointerDereferenceExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vtotal_2072)
}

from Function func, Parameter vtotal_2072, Variable vi_2075, Variable vstartoff_2075, Variable voffsets_2077, Variable v__ret_warn_on_2150
where
not func_0(vtotal_2072, vi_2075, voffsets_2077, func)
and not func_5(vtotal_2072, vstartoff_2075, v__ret_warn_on_2150)
and vtotal_2072.getType().hasName("unsigned int *")
and func_6(vtotal_2072)
and vi_2075.getType().hasName("unsigned int")
and vstartoff_2075.getType().hasName("unsigned int")
and voffsets_2077.getType().hasName("unsigned int[4]")
and v__ret_warn_on_2150.getType().hasName("int")
and vtotal_2072.getParentScope+() = func
and vi_2075.getParentScope+() = func
and vstartoff_2075.getParentScope+() = func
and voffsets_2077.getParentScope+() = func
and v__ret_warn_on_2150.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
