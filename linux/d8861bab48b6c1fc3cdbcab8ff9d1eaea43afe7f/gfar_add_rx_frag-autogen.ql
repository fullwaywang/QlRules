/**
 * @name linux-d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f-gfar_add_rx_frag
 * @id cpp/linux/d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f/gfar_add_rx_frag
 * @description linux-d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f-gfar_add_rx_frag 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfirst_2381, Variable vsize_2383) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_2383
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="1574"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__warn_printk")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="gianfar: rx fragment size underflow"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="1575"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="1576"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="1577"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="1578"
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfirst_2381
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

predicate func_18(Parameter vfirst_2381, Variable vsize_2383) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_2383
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfirst_2381
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

predicate func_19(Parameter vskb_2381, Variable vsize_2383) {
	exists(AssignSubExpr target_19 |
		target_19.getLValue().(VariableAccess).getTarget()=vsize_2383
		and target_19.getRValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_19.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_2381)
}

from Function func, Parameter vskb_2381, Parameter vfirst_2381, Variable vsize_2383
where
not func_0(vfirst_2381, vsize_2383)
and not func_18(vfirst_2381, vsize_2383)
and vfirst_2381.getType().hasName("bool")
and vsize_2383.getType().hasName("int")
and func_19(vskb_2381, vsize_2383)
and vskb_2381.getParentScope+() = func
and vfirst_2381.getParentScope+() = func
and vsize_2383.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
