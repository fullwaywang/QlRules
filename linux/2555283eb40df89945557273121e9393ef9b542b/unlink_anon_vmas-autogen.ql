/**
 * @name linux-2555283eb40df89945557273121e9393ef9b542b-unlink_anon_vmas
 * @id cpp/linux/2555283eb40df89945557273121e9393ef9b542b/unlink-anon-vmas
 * @description linux-2555283eb40df89945557273121e9393ef9b542b-unlink_anon_vmas 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(PostfixDecrExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="num_children"
		and target_0.getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(PostfixDecrExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="num_active_vmas"
		and target_1.getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vanon_vma_437) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="num_children"
		and target_2.getQualifier().(VariableAccess).getTarget()=vanon_vma_437)
}

predicate func_3(Variable vanon_vma_437) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="num_active_vmas"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vanon_vma_437
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="967"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="968"
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal)
}

predicate func_14(Variable vanon_vma_403) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="parent"
		and target_14.getQualifier().(VariableAccess).getTarget()=vanon_vma_403)
}

predicate func_15(Parameter vvma_393) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="anon_vma"
		and target_15.getQualifier().(VariableAccess).getTarget()=vvma_393)
}

predicate func_17(Function func) {
	exists(PostfixDecrExpr target_17 |
		target_17.getOperand().(PointerFieldAccess).getTarget().getName()="degree"
		and target_17.getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(PostfixDecrExpr target_18 |
		target_18.getOperand().(PointerFieldAccess).getTarget().getName()="degree"
		and target_18.getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Variable vanon_vma_437) {
	exists(PointerFieldAccess target_19 |
		target_19.getTarget().getName()="degree"
		and target_19.getQualifier().(VariableAccess).getTarget()=vanon_vma_437)
}

from Function func, Parameter vvma_393, Variable vanon_vma_403, Variable vanon_vma_437
where
not func_0(func)
and not func_1(func)
and not func_2(vanon_vma_437)
and not func_3(vanon_vma_437)
and func_14(vanon_vma_403)
and func_15(vvma_393)
and func_17(func)
and func_18(func)
and func_19(vanon_vma_437)
and vvma_393.getType().hasName("vm_area_struct *")
and vanon_vma_403.getType().hasName("anon_vma *")
and vvma_393.getParentScope+() = func
and vanon_vma_403.getParentScope+() = func
and vanon_vma_437.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
