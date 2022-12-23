/**
 * @name linux-dbcc7d57bffc0c8cac9dac11bec548597d59a6a5-get_old_root
 * @id cpp/linux/dbcc7d57bffc0c8cac9dac11bec548597d59a6a5/get_old_root
 * @description linux-dbcc7d57bffc0c8cac9dac11bec548597d59a6a5-get_old_root 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vold_1334, Variable v__ret_warn_on_1361) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("btrfs_tree_read_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("extent_buffer_uptodate")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=v__ret_warn_on_1361
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="2625"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12")
}

predicate func_1(Variable vold_1334, Variable v__ret_warn_on_1361) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("btrfs_tree_read_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("extent_buffer_uptodate")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(NotExpr).getOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_1334
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=v__ret_warn_on_1361
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0).(Literal).getValue()="2625"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="9"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12")
}

predicate func_2(Variable vold_1334) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("free_extent_buffer")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vold_1334)
}

predicate func_3(Variable vold_1334) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("btrfs_clone_extent_buffer")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vold_1334)
}

from Function func, Variable vold_1334, Variable v__ret_warn_on_1361
where
not func_0(vold_1334, v__ret_warn_on_1361)
and not func_1(vold_1334, v__ret_warn_on_1361)
and vold_1334.getType().hasName("extent_buffer *")
and func_2(vold_1334)
and func_3(vold_1334)
and v__ret_warn_on_1361.getType().hasName("int")
and vold_1334.getParentScope+() = func
and v__ret_warn_on_1361.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
